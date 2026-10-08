import os
import re
import io
from typing import List, Dict, Any, Optional
import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="Universal Firewall Policy Extractor",
    page_icon="😊",
    layout="wide"
)

# ---------------------------------------------------------
# Robust Path Normalizer & File Reader
# ---------------------------------------------------------
def clean_path(path_str: str) -> str:
    """Cleans up pasted Windows paths (removes quotes, resolves ~ and env vars)."""
    if not path_str:
        return ""
    # Strip whitespace, double quotes, and single quotes
    clean = path_str.strip().strip('"').strip("'")
    clean = os.path.expanduser(clean)
    clean = os.path.expandvars(clean)
    return os.path.normpath(clean)

def read_local_file(file_path: str) -> str:
    cleaned = clean_path(file_path)
    if not os.path.exists(cleaned):
        raise FileNotFoundError(f"File not found at: '{cleaned}'\nPlease check if the file path is correct.")
    
    encodings_to_try = ["utf-8", "latin-1", "cp1252", "utf-16"]
    for enc in encodings_to_try:
        try:
            with open(cleaned, "r", encoding=enc) as f:
                return f.read()
        except (UnicodeDecodeError, TypeError):
            continue
            
    with open(cleaned, "r", encoding="utf-8", errors="replace") as f:
        return f.read()

# ---------------------------------------------------------
# Industrial State-Machine Fortinet Parser (Captures ALL Rules)
# ---------------------------------------------------------
def parse_fortigate_full(content: str) -> List[Dict[str, Any]]:
    """
    State-machine parser that correctly traverses config hierarchies,
    captures all VDOM policies, and does not trip on inner 'end' or 'next'.
    """
    rules: List[Dict[str, Any]] = []
    lines = content.splitlines()

    inside_firewall_policy = False
    inside_rule = False
    current_rule: Dict[str, Any] = {}
    current_vdom = "root"
    raw_lines_buffer: List[str] = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # Track VDOM context if present
        if stripped.lower().startswith("edit ") and not inside_firewall_policy:
            parts = stripped.split()
            if len(parts) > 1 and not inside_rule:
                current_vdom = parts[1].strip('"\'')

        # Detect start of firewall policy table
        if stripped.lower() == "config firewall policy":
            inside_firewall_policy = True
            continue

        if inside_firewall_policy:
            # Check if this rule block ends
            if stripped.lower() == "end" and not inside_rule:
                inside_firewall_policy = False
                continue

            # Detect individual rule start: 'edit <id>'
            edit_match = re.match(r"^edit\s+(\d+)", stripped, re.IGNORECASE)
            if edit_match:
                inside_rule = True
                rule_id = edit_match.group(1)
                current_rule = {
                    "Rule_ID": rule_id,
                    "Rule_Name": "",
                    "VDOM": current_vdom,
                    "Action": "ALLOW",
                    "Source_Zone": "any",
                    "Source_IP_Network": "any",
                    "Destination_Zone": "any",
                    "Destination_IP_Network": "any",
                    "Service_Port_Protocol": "any",
                    "Schedule": "always",
                    "Status": "enabled",
                    "Logging": "DISABLED",
                    "Comments": "",
                }
                raw_lines_buffer = [stripped]
                continue

            if inside_rule:
                raw_lines_buffer.append(stripped)

                # End of current rule
                if stripped.lower() == "next":
                    inside_rule = False
                    current_rule["Raw_Config"] = "\n".join(raw_lines_buffer)
                    # Use ID if Name is empty
                    if not current_rule["Rule_Name"]:
                        current_rule["Rule_Name"] = f"Policy_{current_rule['Rule_ID']}"
                    rules.append(current_rule)
                    current_rule = {}
                    raw_lines_buffer = []
                    continue

                # Parse 'set' key-value statements
                if stripped.lower().startswith("set "):
                    tokens = stripped[4:].strip().split(maxsplit=1)
                    if len(tokens) == 2:
                        key = tokens[0].lower()
                        val = tokens[1].strip()
                        # Extract quoted values cleanly
                        cleaned_val = ", ".join([v.strip('"\'') for v in re.findall(r'"[^"]*"|\S+', val)])

                        if key == "name":
                            current_rule["Rule_Name"] = cleaned_val
                        elif key == "srcintf":
                            current_rule["Source_Zone"] = cleaned_val
                        elif key == "dstintf":
                            current_rule["Destination_Zone"] = cleaned_val
                        elif key == "srcaddr":
                            current_rule["Source_IP_Network"] = cleaned_val
                        elif key == "dstaddr":
                            current_rule["Destination_IP_Network"] = cleaned_val
                        elif key == "service":
                            current_rule["Service_Port_Protocol"] = cleaned_val
                        elif key == "action":
                            act = cleaned_val.upper()
                            current_rule["Action"] = "ALLOW" if act == "ACCEPT" else ("DENY" if act == "DENY" else act)
                        elif key == "status":
                            current_rule["Status"] = cleaned_val.lower()
                        elif key == "logtraffic":
                            current_rule["Logging"] = "ENABLED" if cleaned_val.lower() in ["all", "utm"] else "DISABLED"
                        elif key == "comments":
                            current_rule["Comments"] = cleaned_val
                        elif key == "schedule":
                            current_rule["Schedule"] = cleaned_val

    return rules

# ---------------------------------------------------------
# Cisco & Generic Parsers
# ---------------------------------------------------------
def parse_cisco_asa(content: str) -> List[Dict[str, Any]]:
    rules = []
    pattern = re.compile(
        r'access-list\s+(\S+)\s+(?:extended\s+)?(permit|deny)\s+(\S+)\s+(.+)',
        re.IGNORECASE
    )
    for line in content.splitlines():
        line_str = line.strip()
        m = pattern.match(line_str)
        if m:
            acl_name, action, protocol, rest = m.groups()
            parts = rest.split()
            rules.append({
                "Rule_ID": acl_name,
                "Rule_Name": acl_name,
                "VDOM": "N/A",
                "Action": action.upper(),
                "Source_Zone": "N/A",
                "Source_IP_Network": parts[0] if len(parts) > 0 else "any",
                "Destination_Zone": "N/A",
                "Destination_IP_Network": parts[1] if len(parts) > 1 else "any",
                "Service_Port_Protocol": protocol,
                "Schedule": "always",
                "Status": "enabled",
                "Logging": "ENABLED" if "log" in line_str.lower() else "DISABLED",
                "Comments": "",
                "Raw_Config": line_str
            })
    return rules

def extract_all_policies(content: str) -> pd.DataFrame:
    # 1. Fortinet detection
    if "config firewall policy" in content.lower():
        rules = parse_fortigate_full(content)
        if rules:
            return pd.DataFrame(rules)

    # 2. Cisco ASA / IOS detection
    if re.search(r'access-list\s+\S+\s+(?:extended\s+)?(?:permit|deny)', content, re.IGNORECASE):
        rules = parse_cisco_asa(content)
        if rules:
            return pd.DataFrame(rules)

    # Return empty template if format doesn't match
    return pd.DataFrame(columns=[
        "Rule_ID", "Rule_Name", "VDOM", "Action", "Source_Zone", "Source_IP_Network",
        "Destination_Zone", "Destination_IP_Network", "Service_Port_Protocol",
        "Schedule", "Status", "Logging", "Comments", "Raw_Config"
    ])

# ---------------------------------------------------------
# Excel Generator
# ---------------------------------------------------------
def generate_excel_bytes(df: pd.DataFrame) -> bytes:
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name="Firewall_Policies")
        worksheet = writer.sheets["Firewall_Policies"]
        for col in worksheet.columns:
            max_len = max(len(str(cell.value or '')) for cell in col)
            worksheet.column_dimensions[col[0].column_letter].width = min(max(max_len + 3, 12), 40)
    return output.getvalue()

# ---------------------------------------------------------
# Streamlit Interface
# ---------------------------------------------------------
st.title("😊Universal Firewall Policy Extractor")
st.markdown("Extracts **all** policies from Fortinet FortiOS (`config firewall policy`), Cisco, and other configs into Excel.")

tab_path, tab_upload = st.tabs(["📁 Local File Path", "📤 File Upload"])

with tab_path:
    local_path = st.text_input(
        "Enter Absolute or Relative Local File Path:",
        placeholder=r"C:\Users\HP\OneDrive\Desktop\firewall.conf"
    )
    if st.button("Load Local File", key="btn_load"):
        if not local_path.strip():
            st.error("Please enter a valid file path.")
        else:
            try:
                sanitized = clean_path(local_path)
                content = read_local_file(sanitized)
                st.session_state["raw_content"] = content
                st.session_state["file_name"] = os.path.splitext(os.path.basename(sanitized))[0]
                st.success(f"Loaded `{os.path.basename(sanitized)}` ({len(content.splitlines())} lines).")
            except Exception as e:
                st.error(str(e))

with tab_upload:
    uploaded = st.file_uploader("Upload Firewall Config File", type=["txt", "cfg", "conf", "log"])
    if uploaded:
        content = uploaded.read().decode("utf-8", errors="replace")
        st.session_state["raw_content"] = content
        st.session_state["file_name"] = os.path.splitext(uploaded.name)[0]
        st.success(f"Uploaded `{uploaded.name}` ({len(content.splitlines())} lines).")

if "raw_content" in st.session_state:
    content = st.session_state["raw_content"]
    
    with st.expander("📄 View File Preview (First 40 Lines)", expanded=False):
        st.code("\n".join(content.splitlines()[:40]))

    if st.button("🚀 Extract All Firewall Policies to Excel", type="primary"):
        with st.spinner("Processing full configuration file..."):
            df = extract_all_policies(content)
            
        if df.empty:
            st.warning("No firewall policies could be found. Ensure the file contains `config firewall policy` or `access-list` definitions.")
        else:
            st.session_state["extracted_df"] = df
            st.session_state["excel_bytes"] = generate_excel_bytes(df)
            st.success(f"Extracted {len(df)} total policies!")

if "extracted_df" in st.session_state:
    df = st.session_state["extracted_df"]
    excel_data = st.session_state["excel_bytes"]
    base_name = st.session_state.get("file_name", "firewall")
    out_filename = f"{base_name}_all_policies.xlsx"

    st.subheader(f"📊 Extracted Policies ({len(df)} rules)")
    st.dataframe(df, use_container_width=True)

    col1, col2 = st.columns([1, 2])
    with col1:
        st.download_button(
            label="📥 Download Excel File",
            data=excel_data,
            file_name=out_filename,
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    with col2:
        default_save = os.path.abspath(out_filename)
        save_path = st.text_input("Save directly to local path:", value=default_save)
        if st.button("💾 Save to Local Path"):
            try:
                target = clean_path(save_path)
                with open(target, "wb") as f:
                    f.write(excel_data)
                st.success(f"File successfully saved to `{target}`")
            except Exception as ex:
                st.error(f"Failed to save file: {ex}")