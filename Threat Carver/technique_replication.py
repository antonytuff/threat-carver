import streamlit as st
import yaml
import requests

# URL to the Atomic Red Team repository
ATOMIC_RED_TEAM_BASE_URL = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics"

@st.cache_data  # Cache the data to prevent re-downloading on every interaction
def load_atomic_red_team_data(technique_id):
    """
    Load Atomic Red Team test data for a specific technique ID.
    
    Args:
        technique_id (str): The technique ID (e.g., T1078.001)
    
    Returns:
        dict: The parsed YAML data containing Atomic Red Team tests for the technique
    """
    # Format the URL to the specific technique's YAML file
    url = f"{ATOMIC_RED_TEAM_BASE_URL}/{technique_id}/{technique_id}.yaml"
    
    try:
        resp = requests.get(url)
        resp.raise_for_status()
        # Parse the YAML content
        atomic_data = yaml.safe_load(resp.text)
        return atomic_data
    except requests.exceptions.RequestException as e:
        # Handle the case where the technique doesn't have Atomic Red Team tests
        return None
    except yaml.YAMLError as e:
        # Handle YAML parsing errors
        st.error(f"Error parsing YAML for technique {technique_id}: {str(e)}")
        return None

def display_technique_replication_page(techniques_dict):
    """
    Display the Technique Replication page.
    
    Args:
        techniques_dict (dict): Dictionary of techniques from MITRE ATT&CK
    """
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-header">🧪 Technique Replication with Atomic Red Team</div>', unsafe_allow_html=True)
    
    st.markdown("""
    This page allows you to explore Atomic Red Team tests for MITRE ATT&CK techniques. 
    Atomic Red Team is a library of tests mapped to the MITRE ATT&CK framework. 
    These tests are small, highly portable detection tests mapped to specific ATT&CK techniques.
    """)
    
    # Search for techniques
    technique_search = st.text_input("🔍 Search for techniques by ID, name, or description", "")
    
    # Get all techniques
    all_techniques = list(techniques_dict.values())
    
    # Filter techniques based on search
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
    else:
        filtered_techniques = all_techniques[:100]  # Limit to 100 techniques if no search term
    
    # Display technique count
    st.markdown(f"**Found {len(filtered_techniques)} techniques**" + (" (showing first 100)" if not technique_search and len(all_techniques) > 100 else ""))
    
    # Create a DataFrame for display
    if filtered_techniques:
        import pandas as pd
        technique_df = pd.DataFrame([{
            "ID": tech["tech_id"],
            "Name": tech["name"],
            "Tactics": ", ".join(tech.get("tactics", []))
        } for tech in filtered_techniques])
        
        st.dataframe(technique_df, use_container_width=True)
        
        # Select a technique to view details
        selected_technique_id = st.selectbox(
            "Select a technique to view Atomic Red Team tests:",
            options=[f"{tech['tech_id']} - {tech['name']}" for tech in filtered_techniques]
        )
        
        # Display technique details and Atomic Red Team tests
        if selected_technique_id:
            tech_id = selected_technique_id.split(" - ")[0]
            technique = next((t for t in filtered_techniques if t["tech_id"] == tech_id), None)
            
            if technique:
                st.markdown("""
                <div class="card">
                    <div class="card-header">Technique Details</div>
                """, unsafe_allow_html=True)
                
                st.markdown(f"**ID:** {technique['tech_id']}")
                st.markdown(f"**Name:** {technique['name']}")
                st.markdown(f"**Tactics:** {', '.join(technique.get('tactics', []))}")
                st.markdown("**Description:**")
                st.markdown(f"{technique.get('description', 'No description available.')}")
                
                st.markdown("</div>", unsafe_allow_html=True)
                
                # Display Atomic Red Team tests
                display_atomic_red_team_tests(technique["tech_id"])
    else:
        st.warning("No techniques found matching your search criteria.")
    
    st.markdown('</div>', unsafe_allow_html=True)

def display_atomic_red_team_tests(technique_id):
    """
    Display Atomic Red Team tests for a specific technique.
    
    Args:
        technique_id (str): The technique ID (e.g., T1078.001)
    """
    atomic_data = load_atomic_red_team_data(technique_id)
    
    if not atomic_data:
        st.warning(f"No Atomic Red Team tests available for technique {technique_id}")
        return
    
    # Display technique information from Atomic Red Team
    st.markdown(f"## Atomic Red Team Tests for {technique_id}")
    st.markdown(f"**Technique Name:** {atomic_data.get('display_name', 'Unknown')}")
    
    # Display each atomic test
    for i, test in enumerate(atomic_data.get('atomic_tests', [])):
        with st.expander(f"Test #{i+1}: {test.get('name', 'Unnamed Test')} ({test.get('supported_platforms', ['Unknown'])})", expanded=i==0):
            # Description
            st.markdown("### Description")
            st.markdown(test.get('description', 'No description available'))
            
            # Supported platforms
            platforms = test.get('supported_platforms', [])
            st.markdown(f"**Supported Platforms:** {', '.join(platforms)}")
            
            # Dependencies
            if 'dependencies' in test and test['dependencies']:
                st.markdown("### Dependencies")
                for dep in test['dependencies']:
                    st.markdown(f"- **{dep.get('description', 'Dependency')}**")
                    if 'prereq_command' in dep:
                        st.markdown("  Check command:")
                        st.code(dep.get('prereq_command', ''), language='bash')
                    if 'get_prereq_command' in dep:
                        st.markdown("  Install command:")
                        st.code(dep.get('get_prereq_command', ''), language='bash')
            
            # Input arguments
            if 'input_arguments' in test and test['input_arguments']:
                st.markdown("### Input Arguments")
                import pandas as pd
                args_data = []
                for arg_name, arg_details in test['input_arguments'].items():
                    args_data.append({
                        "Argument": arg_name,
                        "Description": arg_details.get('description', ''),
                        "Type": arg_details.get('type', ''),
                        "Default": str(arg_details.get('default', ''))
                    })
                st.table(pd.DataFrame(args_data))
            
            # Execution steps
            st.markdown("### How to Replicate")
            
            # Executor type
            executor = test.get('executor', {})
            executor_type = executor.get('name', 'Unknown')
            st.markdown(f"**Executor Type:** {executor_type}")
            
            # Elevation required
            if executor.get('elevation_required', False):
                st.markdown("⚠️ **Requires Administrator/Root privileges**")
            
            # Command to execute
            if 'command' in executor:
                st.markdown("**Command:**")
                st.code(executor['command'], language='bash')
            
            # Cleanup command
            if 'cleanup_command' in executor:
                st.markdown("**Cleanup Command:**")
                st.code(executor['cleanup_command'], language='bash')
            
            # Additional details
            if test.get('references'):
                st.markdown("### References")
                for ref in test['references']:
                    st.markdown(f"- [{ref}]({ref})")
