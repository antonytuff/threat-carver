import requests
import json
import pandas as pd
import streamlit as st
import plotly.express as px
from datetime import datetime
import yaml

# Import the technique replication module
from technique_replication import display_technique_replication_page

# Set page configuration
st.set_page_config(
    page_title="Threat Carver",
    page_icon="🔪",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load external CSS
def load_css(file_name):
    with open(file_name) as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

# Load the external CSS file
load_css('styles.css')

# URL to the latest Enterprise ATT&CK data (MITRE CTI repository)
ATTACK_JSON_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

@st.cache_data  # Cache the data to prevent re-downloading on every interaction
def load_attack_data():
    resp = requests.get(ATTACK_JSON_URL)
    resp.raise_for_status()
    return resp.json()

# Load and parse the ATT&CK data
attack_data = load_attack_data()

# Dictionaries to store techniques and groups
techniques_dict = {}
groups_dict = {}

for obj in attack_data.get("objects", []):
    o_type = obj.get("type")
    if o_type == "attack-pattern":
        tech_stix_id = obj.get("id")
        name = obj.get("name", "")
        description = obj.get("description", "")
        # Get technique external ID (e.g., T1234 or T1234.001)
        tech_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id")
                break
        # Get tactics from kill_chain_phases
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name", "").startswith("mitre"):
                # phase_name is the tactic name (like "Defense Evasion")
                tactics.append(phase.get("phase_name"))
        techniques_dict[tech_stix_id] = {
            "tech_id": tech_id,
            "name": name,
            "description": description,
            "tactics": tactics
        }
    elif o_type == "intrusion-set":
        group_stix_id = obj.get("id")
        group_name = obj.get("name", "")
        group_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                group_id = ref.get("external_id")
                break
        groups_dict[group_stix_id] = {
            "name": group_name,
            "group_id": group_id
        }

# Build mapping from group name to techniques list
group_to_techniques = {}
for obj in attack_data.get("objects", []):
    if obj.get("type") == "relationship" and obj.get("relationship_type") == "uses":
        src_id = obj.get("source_ref")
        tgt_id = obj.get("target_ref")
        if src_id in groups_dict and tgt_id in techniques_dict:
            group_name = groups_dict[src_id]["name"]
            # Copy technique details and add procedure if available
            tech_info = techniques_dict[tgt_id].copy()
            tech_info["procedure"] = obj.get("description", "")
            group_to_techniques.setdefault(group_name, []).append(tech_info)

# App header
st.markdown("""
    <div class="main-header">
        <h1>🔪 Threat Carver</h1>
        <p>Dissect, analyze and expose threat actor techniques with surgical precision</p>
    </div>
""", unsafe_allow_html=True)

# Create sidebar for navigation and filters
with st.sidebar:
    # Custom Threat Carver logo styling
    st.markdown("""
        <div style="text-align: center; margin-bottom: 20px;">
            <h2 style="color: #dc3545; font-weight: bold; margin-bottom: 0;">🔪 Threat Carver</h2>
            <p style="font-size: 0.8rem; color: #6c757d;">Precision Threat Intelligence</p>
        </div>
    """, unsafe_allow_html=True)
    
    st.markdown("### Navigation")
    
    # Updated navigation options
    page = st.radio(
        "Select Page",
        ["Group Analysis", "Technique Explorer", "Technique Replication", "About Attack Framework"]
    )
    
    st.markdown("---")
    
    st.markdown("### Data Information")
    st.markdown(f"**Last Updated:** {datetime.now().strftime('%B %d, %Y')}")
    st.markdown("**Source:** MITRE CTI Repository")
    
    st.markdown("---")
    
    st.markdown("### Help")
    with st.expander("How to use this tool"):
        st.markdown("""
        1. **Group Analysis**: Select a threat group from the dropdown, filter by tactics if needed, and explore their techniques
        2. **Technique Explorer**: Search for specific techniques and view their details
        3. **Technique Replication**: Find specific techniques and view Atomic Red Team tests to replicate them in a controlled environment
        4. Use the search bar to find specific techniques or groups
        5. View detailed information and download as CSV where available
        """)
    
    with st.expander("About Threat Carver"):
        st.markdown("""
        Threat Carver is a powerful threat intelligence tool that leverages the MITRE ATT&CK® framework to provide surgical precision in analyzing adversary tactics and techniques. Our platform enables security professionals to dissect, understand, and counter sophisticated threat actors with confidence and accuracy.
        """)

# Main content based on selected page
if page == "Group Analysis":
    # Create a container for the search and filters
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-header">Search & Filters</div>', unsafe_allow_html=True)
    
    # Search bar with icon
    search_term = st.text_input("🔍 Search Techniques, Groups, or Tactics", "")
    
    # Create two columns for group selection and tactic filtering
    col1, col2 = st.columns(2)
    
    with col1:
        # Group selection with improved styling
        group_names = sorted(group_to_techniques.keys())
        selected_group = st.selectbox("Select a Threat Group:", options=group_names, index=0)
    
    st.markdown('</div>', unsafe_allow_html=True)
    
    if selected_group:
        # Get tactics for filter (unique tactics used by this group's techniques)
        tactic_set = set()
        for tech in group_to_techniques[selected_group]:
            for tactic in tech.get("tactics", []):
                tactic_set.add(tactic)
        tactics_options = sorted(tactic_set)
        
        with col2:
            selected_tactics = st.multiselect("Filter by Tactic:", options=tactics_options, default=[])
        
        # Create a row of stats cards
        st.markdown("<div style='display: flex; gap: 1rem; margin-top: 1.5rem;'>", unsafe_allow_html=True)
        
        # Count total techniques used by this group
        total_techniques = len(group_to_techniques[selected_group])
        
        # Count unique tactics
        unique_tactics = len(tactic_set)
        
        # Count techniques by tactic category
        tactic_counts = {}
        for tech in group_to_techniques[selected_group]:
            for tactic in tech.get("tactics", []):
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        
        # Find most common tactic
        most_common_tactic = max(tactic_counts.items(), key=lambda x: x[1]) if tactic_counts else ("None", 0)
        
        # Stats cards
        st.markdown(f"""
            <div class="stats-card" style="flex: 1;">
                <div class="stats-value">{total_techniques}</div>
                <div class="stats-label">Total Techniques</div>
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown(f"""
            <div class="stats-card" style="flex: 1;">
                <div class="stats-value">{unique_tactics}</div>
                <div class="stats-label">Unique Tactics</div>
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown(f"""
            <div class="stats-card" style="flex: 1;">
                <div class="stats-value">{most_common_tactic[0]}</div>
                <div class="stats-label">Most Common Tactic</div>
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown(f"""
            <div class="stats-card" style="flex: 1;">
                <div class="stats-value">{most_common_tactic[1]}</div>
                <div class="stats-label">Techniques in Most Common</div>
            </div>
        """, unsafe_allow_html=True)
        
        st.markdown("</div>", unsafe_allow_html=True)
        
        # Group Overview in a card
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown(f'<div class="card-header">🧠 Overview of {selected_group}</div>', unsafe_allow_html=True)
        
        # Get group details
        group_description = groups_dict.get(selected_group, {}).get("description", "No description available.")
        group_sector = groups_dict.get(selected_group, {}).get("industry", "No industry information available.")
        
        st.markdown(f"""
            <p><strong>Description:</strong> {group_description}</p>
            <p><strong>Industry Targets:</strong> {group_sector}</p>
            <p><strong>Group ID:</strong> {next((g["group_id"] for g in groups_dict.values() if g["name"] == selected_group), "Unknown")}</p>
        """, unsafe_allow_html=True)
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Filter techniques if tactics are selected
        techniques_list = group_to_techniques[selected_group]
        if selected_tactics:
            techniques_list = [tech for tech in techniques_list 
                              if set(tech.get("tactics", [])) & set(selected_tactics)]

        # Apply enhanced search filter if search term is provided
        if search_term:
            search_term_lower = search_term.lower()
            filtered_techniques = []
            
            for tech in techniques_list:
                # Check all possible fields for the search term
                if (search_term_lower in tech["name"].lower() or 
                    search_term_lower in tech.get("description", "").lower() or
                    (tech["tech_id"] and search_term_lower in tech["tech_id"].lower()) or
                    search_term_lower in tech.get("procedure", "").lower() or
                    any(search_term_lower in tactic.lower() for tactic in tech.get("tactics", []))):
                    filtered_techniques.append(tech)
            
            techniques_list = filtered_techniques
            
            # If no results found in this group but search term exists, offer global search
            if not techniques_list and search_term:
                st.warning(f"No results found for '{search_term}' in the selected group. Would you like to search across all groups?")
                if st.button("Search All Groups"):
                    # Search across all groups
                    global_results = []
                    for group_name, techs in group_to_techniques.items():
                        for tech in techs:
                            if (search_term_lower in tech["name"].lower() or 
                                search_term_lower in tech.get("description", "").lower() or
                                (tech["tech_id"] and search_term_lower in tech["tech_id"].lower()) or
                                search_term_lower in tech.get("procedure", "").lower() or
                                any(search_term_lower in tactic.lower() for tactic in tech.get("tactics", []))):
                                # Add group name to the technique info for display
                                tech_copy = tech.copy()
                                tech_copy["group_name"] = group_name
                                global_results.append(tech_copy)
                    
                    if global_results:
                        st.success(f"Found {len(global_results)} results across all groups")
                        
                        # Create a DataFrame with the global results
                        global_data = []
                        for tech in global_results:
                            global_data.append({
                                "Group": tech["group_name"],
                                "Technique ID": tech["tech_id"],
                                "Technique Name": tech["name"],
                                "Tactic(s)": ", ".join(tech.get("tactics", [])),
                                "Description": tech.get("description", "")[:150] + "..." if tech.get("description", "") else ""
                            })
                        
                        global_df = pd.DataFrame(global_data)
                        st.dataframe(global_df, use_container_width=True)

        # Create a visualization of tactics distribution
        if techniques_list:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.markdown('<div class="card-header">📊 Tactics Distribution</div>', unsafe_allow_html=True)
            
            # Count techniques by tactic
            tactic_distribution = {}
            for tech in techniques_list:
                for tactic in tech.get("tactics", []):
                    tactic_distribution[tactic] = tactic_distribution.get(tactic, 0) + 1
            
            # Create a DataFrame for the chart
            tactic_df = pd.DataFrame({
                'Tactic': list(tactic_distribution.keys()),
                'Count': list(tactic_distribution.values())
            }).sort_values('Count', ascending=False)
            
            # Create a bar chart
            fig = px.bar(
                tactic_df, 
                x='Tactic', 
                y='Count',
                color='Count',
                color_continuous_scale='Blues',
                title=f'Tactics Distribution for {selected_group}',
                labels={'Count': 'Number of Techniques', 'Tactic': 'Tactic Name'}
            )
            fig.update_layout(
                xaxis_title="Tactic",
                yaxis_title="Number of Techniques",
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font=dict(family="Segoe UI, sans-serif", size=12),
                margin=dict(l=20, r=20, t=40, b=20),
            )
            st.plotly_chart(fig, use_container_width=True)
            
            st.markdown('</div>', unsafe_allow_html=True)

        # Prepare DataFrame with enhanced formatting for techniques
        if techniques_list:
            # Format tactics with badges
            def format_tactics(tactics_list):
                if not tactics_list:
                    return ""
                
                badges = []
                for tactic in tactics_list:
                    tactic_slug = tactic.lower().replace(" ", "-")
                    badges.append(f'<span class="badge badge-{tactic_slug}">{tactic}</span>')
                
                return " ".join(badges)
            
            # Create a DataFrame with formatted data
            techniques_data = []
            for tech in techniques_list:
                techniques_data.append({
                    "Technique ID": tech["tech_id"],
                    "Technique Name": tech["name"],
                    "Tactic(s)": format_tactics(tech.get("tactics", [])),
                    "Description": tech.get("description", "")[:150] + "..." if tech.get("description", "") else "",
                    "Procedure Example": tech.get("procedure", "")[:150] + "..." if tech.get("procedure", "") else ""
                })
            
            df = pd.DataFrame(techniques_data)
            
            # Display results in a table with enhanced styling
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.markdown(f'<div class="card-header">🔍 Techniques used by {selected_group} ({len(techniques_list)} results)</div>', unsafe_allow_html=True)
            
            if not df.empty:
                # Convert DataFrame to HTML with custom styling
                html_table = df.to_html(escape=False, index=False, classes='dataframe')
                
                # Display the table in a container
                st.markdown('<div class="table-container">', unsafe_allow_html=True)
                st.markdown(html_table, unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)
                
                # Add export options
                col1, col2 = st.columns(2)
                with col1:
                    # CSV download button
                    csv_data = df.to_csv(index=False)
                    st.download_button(
                        label="📥 Download CSV",
                        data=csv_data,
                        file_name=f"{selected_group}_techniques.csv",
                        mime="text/csv"
                    )
                
                with col2:
                    # JSON download option
                    json_data = df.to_json(orient="records")
                    st.download_button(
                        label="📥 Download JSON",
                        data=json_data,
                        file_name=f"{selected_group}_techniques.json",
                        mime="application/json"
                    )
            else:
                st.markdown('<div class="alert alert-info">No results found based on your filters.</div>', unsafe_allow_html=True)
            
            st.markdown('</div>', unsafe_allow_html=True)
            
            # Add detailed view for selected technique
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.markdown('<div class="card-header">🔎 Technique Details</div>', unsafe_allow_html=True)
            
            # Create a selectbox for technique selection
            technique_options = [f"{tech['tech_id']} - {tech['name']}" for tech in techniques_list]
            if technique_options:
                selected_technique_option = st.selectbox("Select a technique to view details:", technique_options)
                
                # Find the selected technique
                selected_tech_id = selected_technique_option.split(" - ")[0]
                selected_technique = next((tech for tech in techniques_list if tech["tech_id"] == selected_tech_id), None)
                
                if selected_technique:
                    st.markdown(f"### {selected_technique['tech_id']} - {selected_technique['name']}")
                    st.markdown(f"**Tactics:** {format_tactics(selected_technique.get('tactics', []))}", unsafe_allow_html=True)
                    st.markdown("**Description:**")
                    st.markdown(f"{selected_technique.get('description', 'No description available.')}")
                    
                    if selected_technique.get('procedure'):
                        st.markdown("**Procedure Example:**")
                        st.markdown(f"{selected_technique.get('procedure')}")
            else:
                st.markdown("No techniques available to display details.")
            
            st.markdown('</div>', unsafe_allow_html=True)

elif page == "Technique Explorer":
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-header">Technique Explorer</div>', unsafe_allow_html=True)
    
    # Search for techniques
    technique_search = st.text_input("🔍 Search for techniques by ID, name, or description", "")
    
    # Get all techniques
    all_techniques = list(techniques_dict.values())
    
    # Enhanced search for techniques
    if technique_search:
        search_term_lower = technique_search.lower()
        filtered_techniques = []
        
        for tech in all_techniques:
            # Check all possible fields for the search term
            if (search_term_lower in tech["name"].lower() or
                search_term_lower in tech.get("description", "").lower() or
                (tech["tech_id"] and search_term_lower in tech["tech_id"].lower()) or
                any(search_term_lower in tactic.lower() for tactic in tech.get("tactics", []))):
                filtered_techniques.append(tech)
                
        # Also search in procedures across all groups
        for group_name, techs in group_to_techniques.items():
            for tech in techs:
                # Only add if not already in filtered_techniques and contains search term in procedure
                if (tech["tech_id"] not in [t["tech_id"] for t in filtered_techniques] and
                    search_term_lower in tech.get("procedure", "").lower()):
                    filtered_techniques.append(tech)
    else:
        filtered_techniques = all_techniques
    
    # Display technique count
    st.markdown(f"**Found {len(filtered_techniques)} techniques**")
    
    # Create an enhanced DataFrame for display with search highlighting
    if filtered_techniques:
        # Function to highlight search term in text
        def highlight_text(text, search_term):
            if not search_term or not text:
                return text
            
            # For dataframe display, we can't use HTML, so we'll use a simple approach
            # In a full implementation, you could use HTML with CSS for better highlighting
            return text.replace(search_term, f"[{search_term}]")
        
        technique_df = pd.DataFrame([{
            "ID": tech["tech_id"],
            "Name": highlight_text(tech["name"], technique_search) if technique_search else tech["name"],
            "Tactics": ", ".join(tech.get("tactics", [])),
            "Description": highlight_text(tech.get("description", "")[:100] + "..." if tech.get("description", "") else "", 
                                         technique_search)
        } for tech in filtered_techniques])
        
        st.dataframe(technique_df, use_container_width=True)
        
        # Select a technique to view details
        selected_technique_id = st.selectbox(
            "Select a technique to view details:",
            options=[f"{tech['tech_id']} - {tech['name']}" for tech in filtered_techniques]
        )
        
        # Display technique details
        if selected_technique_id:
            tech_id = selected_technique_id.split(" - ")[0]
            technique = next((t for t in filtered_techniques if t["tech_id"] == tech_id), None)
            
            if technique:
                st.markdown("### Technique Details")
                st.markdown(f"**ID:** {technique['tech_id']}")
                st.markdown(f"**Name:** {technique['name']}")
                st.markdown(f"**Tactics:** {', '.join(technique.get('tactics', []))}")
                st.markdown("**Description:**")
                st.markdown(f"{technique.get('description', 'No description available.')}")
                
                # Find groups using this technique
                groups_using = []
                for group_name, techs in group_to_techniques.items():
                    if any(t["tech_id"] == technique["tech_id"] for t in techs):
                        groups_using.append(group_name)
                
                if groups_using:
                    st.markdown("### Groups Using This Technique")
                    for group in groups_using:
                        st.markdown(f"- {group}")
    else:
        st.markdown("No techniques found matching your search criteria.")
    
    st.markdown('</div>', unsafe_allow_html=True)

elif page == "Technique Replication":
    # Use the imported function to display the Technique Replication page
    display_technique_replication_page(techniques_dict)

elif page == "About Attack Framework":
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-header">About the Attack Framework</div>', unsafe_allow_html=True)
    
    st.markdown("""
    ### The Power Behind Threat Carver
    
    Threat Carver is powered by the MITRE ATT&CK® framework, a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. This framework serves as the foundation for our precision threat intelligence, enabling security professionals to dissect and understand threat actor behaviors with surgical accuracy.
    
    ### The ATT&CK Matrix
    
    The ATT&CK Matrix for Enterprise covers the following tactics:
    
    1. **Initial Access**: Techniques used to gain an initial foothold within a network
    2. **Execution**: Techniques that result in adversary-controlled code running on a local or remote system
    3. **Persistence**: Techniques used to maintain access to systems across restarts, changed credentials, and other interruptions
    4. **Privilege Escalation**: Techniques used to gain higher-level permissions on a system or network
    5. **Defense Evasion**: Techniques used to avoid detection throughout their compromise
    6. **Credential Access**: Techniques for stealing credentials like account names and passwords
    7. **Discovery**: Techniques used to gain knowledge about the system and internal network
    8. **Lateral Movement**: Techniques used to move through the environment
    9. **Collection**: Techniques used to gather information relevant to the adversary's objective
    10. **Command and Control**: Techniques used to communicate with systems under their control
    11. **Exfiltration**: Techniques used to steal data from the network
    12. **Impact**: Techniques used to disrupt availability or compromise integrity
    
    ### How to Use This Tool
    
    This tool allows you to explore the MITRE ATT&CK framework in several ways:
    
    1. **Group Analysis**: Examine the techniques used by specific threat groups
    2. **Technique Explorer**: Search and browse all techniques in the framework
    3. **Technique Replication**: Find specific techniques and view Atomic Red Team tests to replicate them in a controlled environment
    4. **About MITRE ATT&CK**: Learn more about the framework and its applications
    
    ### Resources
    
    - [MITRE ATT&CK Website](https://attack.mitre.org/)
    - [MITRE CTI Repository](https://github.com/mitre/cti)
    - [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
    - [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
    """)
    
    st.markdown('<div class="footer">Created with Streamlit and Python | Data from MITRE CTI</div>', unsafe_allow_html=True)
