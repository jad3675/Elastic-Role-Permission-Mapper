#!/usr/bin/env python3
"""
Elastic Role Permission Mapper
A GUI tool to analyze and visualize Elastic Cloud Kibana permissions with detailed sub-feature breakdown
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import webbrowser
import tempfile
import os
from datetime import datetime
from typing import Dict, List, Any
import threading
import re

try:
    from elasticsearch import Elasticsearch
    from elasticsearch.exceptions import AuthenticationException as AuthenticationError
    from elasticsearch.exceptions import ConnectionError as ESConnectionError
except ImportError as e:
    print(f"Please install elasticsearch 8.x: pip install 'elasticsearch>=8.0,<9.0'")
    print(f"Import error details: {e}")
    exit(1)

class KibanaRoleMapper:
    def __init__(self):
        self.es = None
        self.roles_data = {}
        self.mappings_data = {}
        self.connected = False
        
    def connect(self, cloud_id: str, api_key: str) -> bool:
        """Connect to Elastic Cloud - optimized for ES 8.x"""
        try:
            # Parse API key if it's in id:key format
            if ':' in api_key:
                api_key_id, api_key_secret = api_key.split(':', 1)
                auth = (api_key_id, api_key_secret)
            else:
                # Assume it's already base64 encoded
                auth = api_key
            
            # ES 8.x optimized configuration
            self.es = Elasticsearch(
                cloud_id=cloud_id,
                api_key=auth,
                request_timeout=30
            )
            
            # Test connection
            info = self.es.info()
            self.connected = True
            return True
            
        except AuthenticationError:
            raise Exception("Authentication failed. Check your API key.")
        except ESConnectionError:
            raise Exception("Connection failed. Check your Cloud ID.")
        except Exception as e:
            raise Exception(f"Connection error: {str(e)}")
    
    def fetch_data(self) -> Dict:
        """Fetch roles and mappings from Elasticsearch"""
        if not self.connected:
            raise Exception("Not connected to Elasticsearch")
        
        try:
            # Get roles using modern API
            roles_response = self.es.security.get_role()
            self.roles_data = roles_response
            
            # Get role mappings
            try:
                mappings_response = self.es.security.get_role_mapping()
                self.mappings_data = mappings_response
            except Exception as mapping_error:
                # Role mappings might not be available in all configurations
                print(f"Warning: Could not fetch role mappings: {mapping_error}")
                self.mappings_data = {}
            
            # Get cluster info
            cluster_info = self.es.info()
            
            return {
                'roles': self.roles_data,
                'mappings': self.mappings_data,
                'cluster_info': cluster_info,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            raise Exception(f"Failed to fetch data: {str(e)}")
    
    def parse_detailed_privileges(self, privileges: List[str]) -> Dict:
        """Parse privileges into detailed structure with sub-features"""
        detailed_perms = {}
        raw_privileges = list(privileges)  # Store raw privileges
        
        # Kibana features to check
        kibana_features = [
            'discover', 'dashboard', 'visualize', 'canvas', 'maps',
            'ml', 'apm', 'uptime', 'logs', 'infrastructure',
            'siem', 'dev_tools', 'advancedSettings', 'indexPatterns',
            'savedObjectsManagement', 'graph', 'monitoring', 'fleet',
            'osquery', 'security', 'alerts', 'cases', 'enterpriseSearch'
        ]
        
        # Initialize feature structure
        for feature in kibana_features:
            detailed_perms[feature] = {
                'level': 'NONE',
                'privileges': [],
                'sub_features': {}
            }
        
        # Global privileges
        global_privs = []
        other_privs = []
        
        # Parse each privilege
        for priv in privileges:
            if priv in ['all', 'read']:
                global_privs.append(priv)
                # Global 'all' grants admin to all features
                if priv == 'all':
                    for feature in kibana_features:
                        detailed_perms[feature]['level'] = 'ADMIN'
                        detailed_perms[feature]['privileges'].append(priv)
                # Global 'read' grants read to all features
                elif priv == 'read':
                    for feature in kibana_features:
                        if detailed_perms[feature]['level'] == 'NONE':
                            detailed_perms[feature]['level'] = 'READ'
                            detailed_perms[feature]['privileges'].append(priv)
            
            # Feature-specific privileges
            elif priv.startswith('feature_'):
                # Parse feature privilege pattern: feature_<name>.<level>
                match = re.match(r'feature_([^.]+)\.(.+)', priv)
                if match:
                    feature_name = match.group(1)
                    perm_level = match.group(2)
                    
                    if feature_name in detailed_perms:
                        detailed_perms[feature_name]['privileges'].append(priv)
                        
                        # Determine permission level
                        if perm_level == 'all':
                            detailed_perms[feature_name]['level'] = 'ADMIN'
                        elif perm_level == 'read':
                            if detailed_perms[feature_name]['level'] == 'NONE':
                                detailed_perms[feature_name]['level'] = 'READ'
                        elif perm_level.startswith('minimal_'):
                            # Minimal permissions with sub-features
                            minimal_level = perm_level.replace('minimal_', '')
                            if minimal_level == 'all':
                                detailed_perms[feature_name]['level'] = 'WRITE'
                            elif minimal_level == 'read':
                                if detailed_perms[feature_name]['level'] == 'NONE':
                                    detailed_perms[feature_name]['level'] = 'READ'
                            detailed_perms[feature_name]['sub_features']['minimal'] = minimal_level
                        else:
                            # Individual sub-feature permissions
                            detailed_perms[feature_name]['sub_features'][perm_level] = 'granted'
                            if detailed_perms[feature_name]['level'] == 'NONE':
                                detailed_perms[feature_name]['level'] = 'CUSTOM'
                    else:
                        other_privs.append(priv)
            else:
                other_privs.append(priv)
        
        return {
            'features': detailed_perms,
            'global_privileges': global_privs,
            'other_privileges': other_privs,
            'raw_privileges': raw_privileges
        }
    
    def analyze_permissions(self, data: Dict) -> Dict:
        """Analyze role permissions and create structured output with detailed sub-features"""
        roles = data['roles']
        mappings = data['mappings']
        
        # Kibana features to check
        kibana_features = [
            'discover', 'dashboard', 'visualize', 'canvas', 'maps',
            'ml', 'apm', 'uptime', 'logs', 'infrastructure',
            'siem', 'dev_tools', 'advancedSettings', 'indexPatterns',
            'savedObjectsManagement', 'graph', 'monitoring', 'fleet',
            'osquery', 'security', 'alerts', 'cases', 'enterpriseSearch'
        ]
        
        # Analyze each role
        role_analysis = {}
        for role_name, role_data in roles.items():
            analysis = {
                'kibana_permissions': {},
                'detailed_permissions': {},
                'elasticsearch_permissions': {},
                'spaces': []
            }
            
            # Check Kibana application privileges
            applications = role_data.get('applications', [])
            for app in applications:
                if app.get('application') == 'kibana-.kibana':
                    privileges = app.get('privileges', [])
                    spaces = app.get('resources', ['*'])
                    
                    analysis['spaces'] = spaces
                    
                    # Parse detailed privileges
                    detailed_perms = self.parse_detailed_privileges(privileges)
                    analysis['detailed_permissions'] = detailed_perms
                    
                    # Store space-specific permissions
                    analysis['space_permissions'] = {}
                    for space in spaces:
                        space_name = space if space != '*' else 'Default'
                        analysis['space_permissions'][space_name] = {}
                        
                        # Use detailed permissions for each space
                        for feature in kibana_features:
                            feature_data = detailed_perms['features'].get(feature, {})
                            analysis['space_permissions'][space_name][feature] = feature_data.get('level', 'NONE')
                    
                    # Also maintain the global view for compatibility
                    for feature in kibana_features:
                        feature_data = detailed_perms['features'].get(feature, {})
                        analysis['kibana_permissions'][feature] = feature_data.get('level', 'NONE')
            
            # Check Elasticsearch cluster/index privileges
            cluster_privs = role_data.get('cluster', [])
            index_privs = role_data.get('indices', [])
            
            analysis['elasticsearch_permissions'] = {
                'cluster': cluster_privs,
                'indices': index_privs
            }
            
            role_analysis[role_name] = analysis
        
        # Analyze SAML mappings
        saml_analysis = {}
        for mapping_name, mapping_data in mappings.items():
            rules = mapping_data.get('rules', {})
            roles_assigned = mapping_data.get('roles', [])
            
            saml_analysis[mapping_name] = {
                'rules': rules,
                'roles': roles_assigned,
                'enabled': mapping_data.get('enabled', True)
            }
        
        return {
            'roles': role_analysis,
            'saml_mappings': saml_analysis,
            'kibana_features': kibana_features,
            'stats': {
                'total_roles': len(roles),
                'total_mappings': len(mappings),
                'total_features': len(kibana_features)
            }
        }

class KibanaMapperGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Elastic Role Permission Mapper")
        self.root.geometry("800x600")
        
        self.mapper = KibanaRoleMapper()
        self.data = None
        self.analysis = None
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the GUI"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Connection frame
        conn_frame = ttk.LabelFrame(main_frame, text="Elastic Cloud Connection", padding="10")
        conn_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Cloud ID
        ttk.Label(conn_frame, text="Cloud ID:").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        self.cloud_id_var = tk.StringVar()
        cloud_id_entry = ttk.Entry(conn_frame, textvariable=self.cloud_id_var, width=60)
        cloud_id_entry.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # API Key
        ttk.Label(conn_frame, text="API Key (id:secret or base64):").grid(row=2, column=0, sticky=tk.W, pady=(0, 5))
        self.api_key_var = tk.StringVar()
        api_key_entry = ttk.Entry(conn_frame, textvariable=self.api_key_var, width=60, show="*")
        api_key_entry.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Elasticsearch Version Selection
        ttk.Label(conn_frame, text="Target: Elasticsearch 8.x clusters").grid(row=4, column=0, sticky=tk.W, pady=(10, 5))
        version_note = ttk.Label(conn_frame, text="(Enhanced with detailed sub-feature permission analysis)", font=('TkDefaultFont', 8))
        version_note.grid(row=5, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))
        
        # Connect button
        self.connect_btn = ttk.Button(conn_frame, text="Connect", command=self.connect_to_elastic)
        self.connect_btn.grid(row=6, column=0, sticky=tk.W)
        
        # Status label
        self.status_var = tk.StringVar(value="Not connected")
        self.status_label = ttk.Label(conn_frame, textvariable=self.status_var)
        self.status_label.grid(row=6, column=1, sticky=tk.E)
        
        # Actions frame
        actions_frame = ttk.LabelFrame(main_frame, text="Actions", padding="10")
        actions_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Fetch data button
        self.fetch_btn = ttk.Button(actions_frame, text="Fetch Role Data", 
                                   command=self.fetch_data, state=tk.DISABLED)
        self.fetch_btn.grid(row=0, column=0, padx=(0, 10))
        
        # Generate report button
        self.report_btn = ttk.Button(actions_frame, text="Generate HTML Report", 
                                    command=self.generate_html_report, state=tk.DISABLED)
        self.report_btn.grid(row=0, column=1, padx=(0, 10))
        
        # Open in browser button
        self.browser_btn = ttk.Button(actions_frame, text="Open in Browser", 
                                     command=self.open_in_browser, state=tk.DISABLED)
        self.browser_btn.grid(row=0, column=2, padx=(0, 10))
        
        # Export CSV button
        self.csv_btn = ttk.Button(actions_frame, text="Export to CSV", 
                                 command=self.export_csv, state=tk.DISABLED)
        self.csv_btn.grid(row=0, column=3)
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Results", padding="10")
        results_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Text widget with scrollbar
        text_frame = ttk.Frame(results_frame)
        text_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.results_text = tk.Text(text_frame, wrap=tk.WORD, height=20)
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.results_text.yview)
        self.results_text.configure(yscrollcommand=scrollbar.set)
        
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)
        conn_frame.columnconfigure(0, weight=1)
        
    def connect_to_elastic(self):
        """Connect to Elastic Cloud"""
        cloud_id = self.cloud_id_var.get().strip()
        api_key = self.api_key_var.get().strip()
        
        if not cloud_id or not api_key:
            messagebox.showerror("Error", "Please enter both Cloud ID and API Key")
            return
        
        def connect_thread():
            try:
                self.status_var.set("Connecting...")
                self.connect_btn.config(state=tk.DISABLED)
                
                self.mapper.connect(cloud_id, api_key)
                
                self.status_var.set("Connected successfully")
                self.fetch_btn.config(state=tk.NORMAL)
                self.results_text.insert(tk.END, "✅ Connected to Elasticsearch 8.x cluster successfully\n")
                
            except Exception as e:
                self.status_var.set("Connection failed")
                messagebox.showerror("Connection Error", str(e))
                
            finally:
                self.connect_btn.config(state=tk.NORMAL)
        
        threading.Thread(target=connect_thread, daemon=True).start()
    
    def fetch_data(self):
        """Fetch role and mapping data"""
        def fetch_thread():
            try:
                self.results_text.insert(tk.END, "\n🔄 Fetching role data with detailed permission analysis...\n")
                self.fetch_btn.config(state=tk.DISABLED)
                
                self.data = self.mapper.fetch_data()
                self.analysis = self.mapper.analyze_permissions(self.data)
                
                # Display summary
                stats = self.analysis['stats']
                summary = f"""
📊 Enhanced Data Summary:
• Total Roles: {stats['total_roles']}
• SAML Mappings: {stats['total_mappings']}
• Kibana Features: {stats['total_features']}

✨ Enhancement: Now includes detailed sub-feature permissions!

Roles found:
"""
                for role_name in self.analysis['roles'].keys():
                    summary += f"  • {role_name}\n"
                
                if self.analysis['saml_mappings']:
                    summary += "\nSAML Mappings:\n"
                    for mapping_name in self.analysis['saml_mappings'].keys():
                        summary += f"  • {mapping_name}\n"
                
                self.results_text.insert(tk.END, summary)
                self.report_btn.config(state=tk.NORMAL)
                self.browser_btn.config(state=tk.NORMAL)
                self.csv_btn.config(state=tk.NORMAL)
                
            except Exception as e:
                messagebox.showerror("Fetch Error", str(e))
                
            finally:
                self.fetch_btn.config(state=tk.NORMAL)
        
        threading.Thread(target=fetch_thread, daemon=True).start()
    
    def open_in_browser(self):
        """Generate report and open directly in browser"""
        if not self.analysis:
            messagebox.showerror("Error", "No data available. Please fetch data first.")
            return
        
        try:
            html_content = self.create_html_report()
            
            # Save to temporary file and open
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as f:
                f.write(html_content)
                temp_path = f.name
            
            # Open in browser
            webbrowser.open(f'file://{temp_path}')
            self.results_text.insert(tk.END, "\n📄 Enhanced HTML report with detailed permissions opened in browser\n")
            
        except Exception as e:
            messagebox.showerror("Report Error", f"Failed to generate report: {str(e)}")
    
    def generate_html_report(self):
        """Generate and save HTML report"""
        if not self.analysis:
            messagebox.showerror("Error", "No data available. Please fetch data first.")
            return
        
        try:
            html_content = self.create_html_report()
            
            # Ask user where to save the file
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            file_path = filedialog.asksaveasfilename(
                defaultextension=".html",
                filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
                title="Save Enhanced Kibana Permission Report"
            )
            
            if file_path:
                # Add timestamp to filename if user didn't specify one
                if not file_path.endswith('.html'):
                    file_path += '.html'
                    
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                messagebox.showinfo("Success", f"Enhanced report saved to {file_path}")
                self.results_text.insert(tk.END, f"\n📄 Enhanced HTML report saved to {file_path}\n")
                
        except Exception as e:
            messagebox.showerror("Report Error", f"Failed to generate report: {str(e)}")
    
    def export_csv(self):
        """Export role permissions to CSV"""
        if not self.analysis:
            messagebox.showerror("Error", "No data available. Please fetch data first.")
            return
        
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                title="Export Enhanced Kibana Permissions to CSV"
            )
            
            if file_path:
                # Add timestamp to filename if user didn't specify one
                if not file_path.endswith('.csv'):
                    file_path += '.csv'
                    
                self.create_csv_export(file_path)
                messagebox.showinfo("Success", f"Enhanced CSV exported to {file_path}")
                self.results_text.insert(tk.END, f"\n📊 Enhanced CSV exported to {file_path}\n")
                
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export CSV: {str(e)}")
    
    def create_html_report(self) -> str:
        """Create enhanced HTML report content with detailed sub-feature permissions"""
        roles = self.analysis['roles']
        mappings = self.analysis['saml_mappings']
        features = self.analysis['kibana_features']
        stats = self.analysis['stats']
        cluster_info = self.data['cluster_info']
        
        # Create permission matrix table (existing functionality)
        matrix_rows = ""
        for role_name, role_data in roles.items():
            perms = role_data['kibana_permissions']
            safe_role_name = str(role_name).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
            row = f"<tr><td><strong>{safe_role_name}</strong></td>"
            
            for feature in features:
                perm_level = perms.get(feature, 'NONE')
                css_class = f"permission-{perm_level.lower()}"
                row += f'<td class="{css_class}">{perm_level}</td>'
            
            row += "</tr>"
            matrix_rows += row
        
        # Create detailed permissions section (NEW)
        detailed_perms_html = ""
        for role_name, role_data in roles.items():
            detailed_perms = role_data.get('detailed_permissions', {})
            if detailed_perms:
                safe_role_name = str(role_name).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
                
                # Global privileges
                global_privs = detailed_perms.get('global_privileges', [])
                global_badges = ""
                for priv in global_privs:
                    global_badges += f'<span class="global-privilege">{priv}</span> '
                
                # Raw privileges for advanced users
                raw_privs = detailed_perms.get('raw_privileges', [])
                raw_priv_count = len(raw_privs)
                
                # Feature breakdown
                feature_breakdown = ""
                features_data = detailed_perms.get('features', {})
                for feature, feature_data in features_data.items():
                    if feature_data.get('level', 'NONE') != 'NONE':
                        level = feature_data['level']
                        privileges = feature_data.get('privileges', [])
                        sub_features = feature_data.get('sub_features', {})
                        
                        # Create feature card
                        feature_display = feature.replace('_', ' ').title()
                        level_class = level.lower()
                        
                        # Sub-features display
                        sub_feature_html = ""
                        if sub_features:
                            sub_feature_html = '<div class="sub-features">'
                            for sub_feat, sub_val in sub_features.items():
                                if sub_feat == 'minimal':
                                    sub_feature_html += f'<span class="sub-feature minimal">Minimal: {sub_val}</span>'
                                else:
                                    sub_feature_html += f'<span class="sub-feature">{sub_feat}: {sub_val}</span>'
                            sub_feature_html += '</div>'
                        
                        # Raw privileges for this feature
                        raw_priv_html = ""
                        if privileges:
                            raw_priv_html = f'<div class="raw-privileges" style="display: none;" id="raw-{safe_role_name}-{feature}">'
                            for priv in privileges:
                                raw_priv_html += f'<code class="privilege-code">{priv}</code>'
                            raw_priv_html += '</div>'
                        
                        feature_breakdown += f'''
                        <div class="detailed-feature-card">
                            <div class="feature-header">
                                <span class="feature-name">{feature_display}</span>
                                <span class="feature-level {level_class}">{level}</span>
                                {f'<button class="show-raw" onclick="toggleRawPrivileges(\'{safe_role_name}-{feature}\')">Show Raw</button>' if privileges else ''}
                            </div>
                            {sub_feature_html}
                            {raw_priv_html}
                        </div>
                        '''
                
                # Other privileges (non-feature)
                other_privs = detailed_perms.get('other_privileges', [])
                other_badges = ""
                for priv in other_privs:
                    other_badges += f'<span class="other-privilege">{priv}</span> '
                
                detailed_perms_html += f'''
                <div class="detailed-role-card">
                    <div class="role-header">
                        <h4>{safe_role_name}</h4>
                        <div class="privilege-summary">
                            <span class="priv-count">{raw_priv_count} total privileges</span>
                            <button class="expand-details" onclick="toggleRoleDetails('{safe_role_name}')">
                                <span id="toggle-text-{safe_role_name}">▼ Show Details</span>
                            </button>
                        </div>
                    </div>
                    
                    <div class="role-details" id="details-{safe_role_name}" style="display: none;">
                        {f'<div class="global-section"><strong>Global Privileges:</strong> {global_badges}</div>' if global_badges else ''}
                        
                        <div class="features-section">
                            <strong>Feature Permissions:</strong>
                            <div class="feature-grid">
                                {feature_breakdown if feature_breakdown else '<span class="no-features">No feature-specific permissions</span>'}
                            </div>
                        </div>
                        
                        {f'<div class="other-section"><strong>Other Privileges:</strong> {other_badges}</div>' if other_badges else ''}
                        
                        <div class="raw-section">
                            <strong>All Raw Privileges:</strong>
                            <button class="show-all-raw" onclick="toggleAllRawPrivileges('{safe_role_name}')">
                                <span id="raw-toggle-{safe_role_name}">Show All</span>
                            </button>
                            <div class="all-raw-privileges" id="all-raw-{safe_role_name}" style="display: none;">
                                {' '.join([f'<code class="privilege-code">{priv}</code>' for priv in raw_privs])}
                            </div>
                        </div>
                    </div>
                </div>
                '''
        
        # Create SAML mapping cards (existing functionality)
        mapping_cards = ""
        for mapping_name, mapping_data in mappings.items():
            if mapping_data.get('enabled', True):
                rules = mapping_data.get('rules', {})
                assigned_roles = mapping_data.get('roles', [])
                
                safe_mapping_name = str(mapping_name).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
                
                # Extract SAML groups from rules (simplified)
                saml_groups = []
                if 'any' in rules:
                    for rule in rules['any']:
                        if isinstance(rule, dict) and 'field' in rule and 'groups' in rule['field']:
                            saml_groups.extend(rule['field']['groups'])
                
                # Safely create group and role spans
                group_spans = ""
                for group in saml_groups:
                    safe_group = str(group).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
                    group_spans += f'<span class="saml-group">{safe_group}</span> '
                
                role_spans = ""
                for role in assigned_roles:
                    safe_role = str(role).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
                    role_spans += f'<span class="role-badge">{safe_role}</span> '

                card = f"""
                <div class="mapping-card">
                    <h3>{safe_mapping_name}</h3>
                    <p><strong>SAML Groups:</strong></p>
                    {group_spans if group_spans else '<span class="saml-group">No groups configured</span>'}
                    <p><strong>→ Assigned Roles:</strong></p>
                    {role_spans if role_spans else '<span class="role-badge">No roles assigned</span>'}
                </div>
                """
                mapping_cards += card
        
        # Create role distribution analysis (existing functionality)
        role_types = {
            'admin': 0,
            'editor': 0,
            'viewer': 0,
            'custom': 0
        }
        
        for role_name in roles.keys():
            role_lower = role_name.lower()
            if 'admin' in role_lower or 'superuser' in role_lower:
                role_types['admin'] += 1
            elif 'editor' in role_lower or 'write' in role_lower or 'analyst' in role_lower:
                role_types['editor'] += 1
            elif 'viewer' in role_lower or 'read' in role_lower or 'monitoring' in role_lower:
                role_types['viewer'] += 1
            else:
                role_types['custom'] += 1
        
        # Create role distribution visualization
        role_distribution = ""
        colors = ['#e74c3c', '#f39c12', '#2ecc71', '#9b59b6']
        labels = ['Admin/Superuser', 'Editor/Analyst', 'Viewer/Monitor', 'Custom/Other']
        
        total_roles = sum(role_types.values())
        if total_roles > 0:
            for i, (role_type, count) in enumerate(role_types.items()):
                if count > 0:
                    percentage = (count / total_roles) * 100
                    width = max(percentage, 5)  # Minimum width for visibility
                    role_distribution += f'''
                    <div class="role-bar">
                        <div class="role-label">{labels[i]}: {count} roles</div>
                        <div class="role-progress">
                            <div class="role-fill" style="width: {width}%; background-color: {colors[i]}"></div>
                        </div>
                        <div class="role-percentage">{percentage:.1f}%</div>
                    </div>
                    '''
        else:
            role_distribution = "<p>No role data available</p>"
        
        # Create Elasticsearch cluster privileges section (existing functionality)
        es_privileges_html = ""
        for role_name, role_data in roles.items():
            es_perms = role_data['elasticsearch_permissions']
            cluster_privs = es_perms.get('cluster', [])
            index_privs = es_perms.get('indices', [])
            
            if cluster_privs or index_privs:
                safe_role_name = str(role_name).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
                
                # Handle cluster privileges with collapsible display
                cluster_section = ""
                if cluster_privs:
                    total_cluster_privs = len(cluster_privs)
                    
                    if total_cluster_privs <= 5:
                        # Show all if 5 or fewer
                        cluster_badges = ""
                        for priv in cluster_privs:
                            safe_priv = str(priv).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
                            cluster_badges += f'<span class="es-privilege cluster-priv">{safe_priv}</span> '
                        cluster_section = f'<strong>Cluster:</strong> {cluster_badges}'
                    else:
                        # Show first 3 with expand option
                        preview_badges = ""
                        all_badges = ""
                        for i, priv in enumerate(cluster_privs):
                            safe_priv = str(priv).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
                            badge = f'<span class="es-privilege cluster-priv">{safe_priv}</span>'
                            all_badges += badge + ' '
                            if i < 3:
                                preview_badges += badge + ' '
                        
                        remaining_count = total_cluster_privs - 3
                        cluster_section = f'''
                        <strong>Cluster:</strong>
                        <div class="privilege-container">
                            <div class="privilege-preview" id="cluster-preview-{safe_role_name}">
                                {preview_badges}
                                <div class="privilege-hidden" id="cluster-hidden-{safe_role_name}" style="display: none;">
                                    {all_badges}
                                </div>
                            </div>
                            <button class="privilege-toggle" onclick="toggleClusterPrivileges('{safe_role_name}')" id="toggle-btn-{safe_role_name}">
                                +{remaining_count} more
                            </button>
                        </div>
                        '''
                else:
                    cluster_section = '<strong>Cluster:</strong> <span class="no-privileges">No cluster privileges</span>'
                
                # Handle index privileges with summary
                index_section = ""
                if index_privs:
                    index_count = len(index_privs)
                    
                    # Create detailed index info
                    index_details = []
                    for idx_perm in index_privs:
                        names = idx_perm.get('names', [])
                        privileges = idx_perm.get('privileges', [])
                        if names and privileges:
                            name_list = names if isinstance(names, list) else [str(names)]
                            priv_list = privileges if isinstance(privileges, list) else [str(privileges)]
                            for name in name_list:
                                index_details.append(f"{name}: {', '.join(priv_list)}")
                    
                    if index_details:
                        # Show summary with expandable detail
                        summary_text = f"Index Privileges ({index_count} patterns)"
                        if len(index_details) <= 3:
                            # Show all if few
                            detail_text = '; '.join(index_details)
                            index_section = f'<div class="index-info"><strong>{summary_text}:</strong> {detail_text}</div>'
                        else:
                            # Show summary with expandable detail
                            preview_text = '; '.join(index_details[:2]) + f" ... (+{len(index_details)-2} more)"
                            full_detail = '\\n'.join(index_details)
                            index_section = f'''
                            <div class="index-info">
                                <strong>{summary_text}:</strong> 
                                <span class="index-summary" onclick="toggleIndexDetail('{safe_role_name}-index')">{preview_text}</span>
                                <div class="index-detail" id="{safe_role_name}-index">
                                    {full_detail.replace(chr(10), '<br>')}
                                </div>
                            </div>
                            '''
                
                es_privileges_html += f'''
                <div class="es-role-card">
                    <h4>{safe_role_name}</h4>
                    <div class="cluster-privileges">
                        {cluster_section}
                    </div>
                    {index_section}
                </div>
                '''
        
        # Create space permission cards - FIXED VERSION
        space_cards_html = '<div class="no-spaces">Select a role above to see space-specific permissions</div>'
        
        # Feature headers for matrix
        feature_headers = ''.join([f'<th>{str(feature).title()}</th>' for feature in features])
        
        # Safely get cluster name
        cluster_name = str(cluster_info.get('cluster_name', 'Unknown')).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
        
        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Elastic Role Permission Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f7fa; color: #333; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 2.5em; font-weight: 300; }}
        .header p {{ margin: 10px 0 0 0; opacity: 0.9; }}
        
        /* Role Filter Styles */
        .role-filter {{ background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .filter-header {{ display: flex; align-items: center; gap: 15px; margin-bottom: 15px; }}
        .filter-header h3 {{ margin: 0; color: #2c3e50; }}
        .clear-filter {{ background: #e74c3c; color: white; border: none; padding: 5px 12px; border-radius: 5px; cursor: pointer; font-size: 0.9em; }}
        .clear-filter:hover {{ background: #c0392b; }}
        .role-pills {{ display: flex; flex-wrap: wrap; gap: 8px; }}
        .role-pill {{ background: #f8f9fa; border: 2px solid #dee2e6; padding: 8px 15px; border-radius: 20px; cursor: pointer; transition: all 0.3s ease; font-size: 0.9em; }}
        .role-pill:hover {{ background: #e9ecef; border-color: #adb5bd; }}
        .role-pill.active {{ background: #3498db; color: white; border-color: #3498db; }}
        .role-pill.filtered-out {{ opacity: 0.3; }}
        .search-box {{ width: 100%; padding: 10px; border: 1px solid #dee2e6; border-radius: 5px; margin-bottom: 15px; font-size: 1em; }}
        
        /* Tab Styles */
        .tab-container {{ background: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 30px; }}
        .tab-nav {{ display: flex; border-bottom: 1px solid #ecf0f1; border-radius: 10px 10px 0 0; overflow: hidden; }}
        .tab-btn {{ background: #f8f9fa; border: none; padding: 15px 25px; cursor: pointer; font-size: 1em; font-weight: 500; color: #6c757d; transition: all 0.3s ease; flex: 1; }}
        .tab-btn:hover {{ background: #e9ecef; color: #495057; }}
        .tab-btn.active {{ background: #3498db; color: white; }}
        .tab-content {{ display: none; padding: 25px; }}
        .tab-content.active {{ display: block; }}
        
        /* Detailed Permissions Styles (NEW) */
        .detailed-role-card {{ background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; margin: 15px 0; transition: all 0.3s ease; }}
        .detailed-role-card.filtered-out {{ display: none; }}
        .role-header {{ background: #fff; padding: 20px; border-radius: 8px 8px 0 0; border-bottom: 1px solid #dee2e6; display: flex; justify-content: space-between; align-items: center; }}
        .role-header h4 {{ margin: 0; color: #2c3e50; font-size: 1.2em; }}
        .privilege-summary {{ display: flex; align-items: center; gap: 15px; }}
        .priv-count {{ background: #17a2b8; color: white; padding: 4px 8px; border-radius: 12px; font-size: 0.8em; }}
        .expand-details {{ background: #6c757d; color: white; border: none; padding: 8px 15px; border-radius: 5px; cursor: pointer; font-size: 0.9em; }}
        .expand-details:hover {{ background: #495057; }}
        .role-details {{ padding: 20px; }}
        .global-section, .features-section, .other-section, .raw-section {{ margin: 15px 0; }}
        .global-privilege {{ background: #dc3545; color: white; padding: 3px 8px; border-radius: 12px; font-size: 0.8em; margin: 2px; display: inline-block; }}
        .other-privilege {{ background: #6f42c1; color: white; padding: 3px 8px; border-radius: 12px; font-size: 0.8em; margin: 2px; display: inline-block; }}
        .feature-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; margin-top: 10px; }}
        .detailed-feature-card {{ background: white; border: 1px solid #dee2e6; border-radius: 6px; padding: 15px; }}
        .feature-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .feature-name {{ font-weight: 600; color: #2c3e50; }}
        .feature-level {{ padding: 3px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; }}
        .feature-level.admin {{ background-color: #f8d7da; color: #721c24; }}
        .feature-level.write {{ background-color: #cce5ff; color: #004085; }}
        .feature-level.read {{ background-color: #d4edda; color: #155724; }}
        .feature-level.custom {{ background-color: #fff3cd; color: #856404; }}
        .show-raw {{ background: #28a745; color: white; border: none; padding: 3px 8px; border-radius: 3px; font-size: 0.7em; cursor: pointer; }}
        .show-raw:hover {{ background: #218838; }}
        .sub-features {{ margin-top: 8px; }}
        .sub-feature {{ background: #e9ecef; padding: 2px 6px; border-radius: 8px; font-size: 0.75em; margin: 2px; display: inline-block; color: #495057; }}
        .sub-feature.minimal {{ background: #fff3cd; color: #856404; }}
        .raw-privileges {{ margin-top: 10px; padding: 10px; background: #f8f9fa; border-radius: 4px; border-left: 3px solid #17a2b8; }}
        .privilege-code {{ background: #e9ecef; padding: 2px 6px; border-radius: 3px; font-family: monospace; font-size: 0.8em; margin: 2px; display: inline-block; }}
        .show-all-raw {{ background: #17a2b8; color: white; border: none; padding: 5px 10px; border-radius: 3px; font-size: 0.8em; cursor: pointer; margin: 5px 0; }}
        .show-all-raw:hover {{ background: #138496; }}
        .all-raw-privileges {{ margin-top: 10px; padding: 10px; background: #f1f3f4; border-radius: 4px; max-height: 200px; overflow-y: auto; }}
        .no-features {{ color: #6c757d; font-style: italic; }}
        
        /* Existing styles continue... */
        .section {{ background: white; border-radius: 10px; padding: 25px; margin-bottom: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .section h2 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; margin-top: 0; }}
        .permission-matrix {{ overflow-x: auto; margin: 20px 0; }}
        .matrix-table {{ width: 100%; border-collapse: collapse; font-size: 0.9em; }}
        .matrix-table th {{ background-color: #34495e; color: white; padding: 12px 8px; text-align: center; font-weight: 600; }}
        .matrix-table th.role-header {{ background-color: #2c3e50; text-align: left; min-width: 150px; }}
        .matrix-table td {{ padding: 8px; text-align: center; border: 1px solid #ecf0f1; }}
        .matrix-table tr {{ transition: all 0.3s ease; }}
        .matrix-table tr:nth-child(even) {{ background-color: #f8f9fa; }}
        .matrix-table tr.filtered-out {{ display: none; }}
        .permission-read {{ background-color: #d4edda; color: #155724; font-weight: bold; }}
        .permission-write {{ background-color: #cce5ff; color: #004085; font-weight: bold; }}
        .permission-admin {{ background-color: #f8d7da; color: #721c24; font-weight: bold; }}
        .permission-custom {{ background-color: #fff3cd; color: #856404; font-weight: bold; }}
        .permission-none {{ background-color: #f6f6f6; color: #6c757d; }}
        .saml-mapping {{ display: flex; flex-wrap: wrap; gap: 20px; margin: 20px 0; }}
        .mapping-card {{ flex: 1; min-width: 300px; background: #f8f9fa; border-left: 4px solid #3498db; padding: 20px; border-radius: 5px; transition: all 0.3s ease; }}
        .mapping-card h3 {{ margin-top: 0; color: #2c3e50; }}
        .mapping-card.filtered-out {{ display: none; }}
        .saml-group {{ background: #e3f2fd; padding: 5px 10px; border-radius: 15px; display: inline-block; margin: 2px; font-size: 0.85em; }}
        .role-badge {{ background: #28a745; color: white; padding: 4px 8px; border-radius: 12px; font-size: 0.8em; margin: 2px; display: inline-block; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; margin: 0; }}
        .stat-label {{ font-size: 0.9em; opacity: 0.9; margin: 5px 0 0 0; }}
        .role-distribution {{ margin: 20px 0; }}
        .role-bar {{ display: flex; align-items: center; margin: 15px 0; gap: 15px; }}
        .role-label {{ min-width: 150px; font-weight: 500; }}
        .role-progress {{ flex-grow: 1; background-color: #ecf0f1; border-radius: 10px; height: 20px; position: relative; }}
        .role-fill {{ height: 100%; border-radius: 10px; transition: width 0.3s ease; }}
        .role-percentage {{ min-width: 50px; text-align: right; font-weight: bold; color: #2c3e50; }}
        .es-privileges {{ margin: 20px 0; }}
        .es-role-card {{ background: #f8f9fa; border-left: 4px solid #17a2b8; padding: 15px; margin: 10px 0; border-radius: 5px; transition: all 0.3s ease; }}
        .es-role-card h4 {{ margin: 0 0 10px 0; color: #2c3e50; }}
        .es-role-card.filtered-out {{ display: none; }}
        .cluster-privileges {{ margin: 8px 0; }}
        .privilege-container {{ position: relative; display: flex; flex-wrap: wrap; align-items: center; gap: 5px; }}
        .privilege-preview {{ display: flex; flex-wrap: wrap; gap: 3px; transition: all 0.3s ease; }}
        .privilege-hidden {{ display: flex; flex-wrap: wrap; gap: 3px; margin-top: 5px; }}
        .es-privilege {{ background: #17a2b8; color: white; padding: 3px 8px; border-radius: 12px; font-size: 0.8em; margin: 2px; display: inline-block; }}
        .cluster-priv {{ background: #17a2b8; }}
        .index-priv {{ background: #6f42c1; }}
        .privilege-toggle {{ background: #6c757d; color: white; border: none; padding: 4px 10px; border-radius: 12px; font-size: 0.75em; cursor: pointer; margin-left: 5px; transition: all 0.3s ease; }}
        .privilege-toggle:hover {{ background: #495057; }}
        .privilege-count {{ background: #28a745; color: white; padding: 2px 6px; border-radius: 10px; font-size: 0.7em; font-weight: bold; margin-left: 5px; }}
        .no-privileges {{ color: #6c757d; font-style: italic; }}
        .index-info {{ margin: 8px 0; font-size: 0.9em; color: #495057; position: relative; }}
        .index-summary {{ cursor: pointer; color: #007bff; text-decoration: underline; }}
        .index-detail {{ background: #f8f9fa; padding: 10px; border-radius: 5px; margin-top: 10px; border-left: 3px solid #17a2b8; font-family: monospace; font-size: 0.85em; display: none; line-height: 1.4; }}
        .filter-info {{ background: #e3f2fd; padding: 10px; border-radius: 5px; margin-bottom: 20px; font-style: italic; color: #1976d2; }}
        
        /* Space Cards Styles */
        .space-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }}
        .space-card {{ background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px; transition: all 0.3s ease; }}
        .space-card.filtered-out {{ display: none; }}
        .space-card h4 {{ margin: 0 0 15px 0; color: #2c3e50; font-size: 1.1em; border-bottom: 2px solid #3498db; padding-bottom: 8px; }}
        .space-features {{ display: flex; flex-direction: column; gap: 8px; }}
        .feature-row {{ display: flex; justify-content: space-between; align-items: center; padding: 6px 0; border-bottom: 1px solid #e9ecef; }}
        .feature-row:last-child {{ border-bottom: none; }}
        .feature-name {{ font-weight: 500; color: #495057; text-transform: capitalize; }}
        .feature-permission {{ padding: 3px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; }}
        .feature-permission.write {{ background-color: #cce5ff; color: #004085; }}
        .feature-permission.read {{ background-color: #d4edda; color: #155724; }}
        .feature-permission.none {{ background-color: #f6f6f6; color: #6c757d; }}
        .no-spaces {{ color: #6c757d; font-style: italic; text-align: center; padding: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Elastic Role Permission Report</h1>
            <p>Cluster: {cluster_name} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | ✨ With Detailed Sub-Feature Analysis</p>
        </div>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-number" id="filtered-roles">{stats['total_roles']}</div>
                <div class="stat-label">Roles Shown</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['total_mappings']}</div>
                <div class="stat-label">SAML Mappings</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['total_features']}</div>
                <div class="stat-label">Kibana Features</div>
            </div>
        </div>

        <div class="role-filter">
            <div class="filter-header">
                <h3>🔍 Filter by Role</h3>
                <button class="clear-filter" onclick="clearFilter()" style="display: none;" id="clear-btn">Clear Filter</button>
            </div>
            <input type="text" class="search-box" placeholder="Search roles..." onkeyup="searchRoles(this.value)">
            <div class="role-pills" id="role-pills">
                <!-- Role pills will be populated by JavaScript -->
            </div>
        </div>

        <div class="tab-container">
            <div class="tab-nav">
                <button class="tab-btn active" onclick="switchTab('detailed-tab')">🔬 Detailed Permissions</button>
                <button class="tab-btn" onclick="switchTab('kibana-tab')">🎛️ Kibana Overview</button>
                <button class="tab-btn" onclick="switchTab('cluster-tab')">⚙️ Cluster Privileges</button>
            </div>
            
            <div id="detailed-tab" class="tab-content active">
                <div id="filter-info-detailed" class="filter-info" style="display: none;">
                    Showing detailed permissions for role: <strong id="filtered-role-name-detailed"></strong>
                </div>
                
                <div class="section-content">
                    <h2>🔬 Detailed Permission Analysis</h2>
                    <p style="color: #7f8c8d; margin-bottom: 20px;">
                        This section shows the granular breakdown of each role's permissions, including sub-features, 
                        minimal permissions, and raw privilege strings from Elasticsearch.
                    </p>
                    <div class="detailed-permissions" id="detailed-permissions">
                        {detailed_perms_html if detailed_perms_html else '<p>No detailed permission data available.</p>'}
                    </div>
                </div>
            </div>
            
            <div id="kibana-tab" class="tab-content">
                <div id="filter-info-kibana" class="filter-info" style="display: none;">
                    Showing permissions for role: <strong id="filtered-role-name-kibana"></strong>
                </div>
                
                <div class="section-content">
                    <h2>🏠 Space-Specific Permissions</h2>
                    <div class="space-cards" id="space-cards">
                        {space_cards_html}
                    </div>
                </div>

                <div class="section-content">
                    <h2>📊 Role Permission Matrix</h2>
                    <div class="permission-matrix">
                        <table class="matrix-table">
                            <thead>
                                <tr>
                                    <th class="role-header">Role</th>
                                    {feature_headers}
                                </tr>
                            </thead>
                            <tbody id="matrix-tbody">
                                {matrix_rows}
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="section-content">
                    <h2>🔗 SAML Role Mappings</h2>
                    <div class="saml-mapping" id="saml-mappings">
                        {mapping_cards if mapping_cards else '<p>No SAML mappings configured</p>'}
                    </div>
                </div>

                <div class="section-content">
                    <h2>📊 Role Distribution Analysis</h2>
                    <div class="role-distribution">
                        {role_distribution}
                    </div>
                    <p style="color: #7f8c8d; font-style: italic; margin-top: 20px;">
                        This analysis categorizes your {stats['total_roles']} roles by their apparent function based on naming patterns.
                    </p>
                </div>
            </div>
            
            <div id="cluster-tab" class="tab-content">
                <div id="filter-info-cluster" class="filter-info" style="display: none;">
                    Showing cluster privileges for role: <strong id="filtered-role-name-cluster"></strong>
                </div>
                
                <div class="section-content">
                    <h2>⚙️ Elasticsearch Cluster Privileges</h2>
                    <div class="es-privileges" id="es-privileges">
                        {es_privileges_html if es_privileges_html else '<p>No Elasticsearch cluster privileges found in roles.</p>'}
                    </div>
                    <p style="color: #7f8c8d; font-style: italic;">
                        Shows the Elasticsearch cluster and index-level permissions granted by each role.
                    </p>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Role data for filtering and space permissions
        const roleData = {json.dumps([role_name for role_name in roles.keys()])};
        const roleSpaceData = {json.dumps({role_name: role_data.get('space_permissions', {}) for role_name, role_data in roles.items()})};
        let selectedRole = null;
        
        // Initialize role pills
        function initializeRolePills() {{
            const pillsContainer = document.getElementById('role-pills');
            roleData.forEach(role => {{
                const pill = document.createElement('div');
                pill.className = 'role-pill';
                pill.textContent = role;
                pill.onclick = () => filterByRole(role);
                pill.setAttribute('data-role', role);
                pillsContainer.appendChild(pill);
            }});
        }}
        
        // Filter by role
        function filterByRole(roleName) {{
            selectedRole = roleName;
            
            // Update pill states
            document.querySelectorAll('.role-pill').forEach(pill => {{
                if (pill.getAttribute('data-role') === roleName) {{
                    pill.classList.add('active');
                }} else {{
                    pill.classList.remove('active');
                }}
            }});
            
            // Filter matrix table rows
            document.querySelectorAll('#matrix-tbody tr').forEach(row => {{
                const roleCell = row.querySelector('td strong');
                if (roleCell && roleCell.textContent === roleName) {{
                    row.classList.remove('filtered-out');
                }} else {{
                    row.classList.add('filtered-out');
                }}
            }});
            
            // Filter SAML mapping cards
            document.querySelectorAll('.mapping-card').forEach(card => {{
                const roleBadges = card.querySelectorAll('.role-badge');
                let hasRole = false;
                roleBadges.forEach(badge => {{
                    if (badge.textContent === roleName) {{
                        hasRole = true;
                    }}
                }});
                if (hasRole) {{
                    card.classList.remove('filtered-out');
                }} else {{
                    card.classList.add('filtered-out');
                }}
            }});
            
            // Filter ES privilege cards
            document.querySelectorAll('.es-role-card').forEach(card => {{
                const cardTitle = card.querySelector('h4');
                if (cardTitle && cardTitle.textContent === roleName) {{
                    card.classList.remove('filtered-out');
                }} else {{
                    card.classList.add('filtered-out');
                }}
            }});
            
            // Filter detailed permission cards
            document.querySelectorAll('.detailed-role-card').forEach(card => {{
                const cardTitle = card.querySelector('.role-header h4');
                if (cardTitle && cardTitle.textContent === roleName) {{
                    card.classList.remove('filtered-out');
                }} else {{
                    card.classList.add('filtered-out');
                }}
            }});
            
            // Update space cards
            updateSpaceCards(roleName);
            
            // Show filter info
            document.getElementById('filter-info-kibana').style.display = 'block';
            document.getElementById('filter-info-cluster').style.display = 'block';
            document.getElementById('filter-info-detailed').style.display = 'block';
            document.getElementById('filtered-role-name-kibana').textContent = roleName;
            document.getElementById('filtered-role-name-cluster').textContent = roleName;
            document.getElementById('filtered-role-name-detailed').textContent = roleName;
            
            // Show clear button
            document.getElementById('clear-btn').style.display = 'inline-block';
            
            // Update filtered roles count
            document.getElementById('filtered-roles').textContent = '1';
        }}
        
        // Update space cards based on selected role
        function updateSpaceCards(roleName) {{
            const spaceContainer = document.getElementById('space-cards');
            
            // Get role space data
            const selectedRoleSpaces = roleSpaceData[roleName] || {{}};
            
            if (Object.keys(selectedRoleSpaces).length === 0) {{
                // No space data available, show default message
                spaceContainer.innerHTML = `
                    <div class="space-card">
                        <h4>🏠 Default Space</h4>
                        <div class="space-features">
                            <div class="feature-row">
                                <span class="feature-name">Role: <strong>${{roleName}}</strong></span>
                                <span class="feature-permission read">Global permissions apply to all spaces</span>
                            </div>
                        </div>
                    </div>
                `;
            }} else {{
                // Build space cards from actual data
                let spaceCardsHtml = '';
                for (const [spaceName, spaceFeatures] of Object.entries(selectedRoleSpaces)) {{
                    let featureRows = '';
                    let hasPermissions = false;
                    
                    for (const [feature, permission] of Object.entries(spaceFeatures)) {{
                        if (permission !== 'NONE') {{
                            hasPermissions = true;
                            const featureDisplay = feature.replace(/_/g, ' ').replace(/\\b\\w/g, l => l.toUpperCase());
                            const permClass = permission.toLowerCase();
                            featureRows += `
                                <div class="feature-row">
                                    <span class="feature-name">${{featureDisplay}}</span>
                                    <span class="feature-permission ${{permClass}}">${{permission}}</span>
                                </div>
                            `;
                        }}
                    }}
                    
                    if (hasPermissions) {{
                        spaceCardsHtml += `
                            <div class="space-card">
                                <h4>🏠 ${{spaceName}} Space</h4>
                                <div class="space-features">
                                    ${{featureRows}}
                                </div>
                            </div>
                        `;
                    }}
                }}
                
                if (spaceCardsHtml) {{
                    spaceContainer.innerHTML = spaceCardsHtml;
                }} else {{
                    spaceContainer.innerHTML = `
                        <div class="space-card">
                            <h4>🏠 Default Space</h4>
                            <div class="space-features">
                                <div class="feature-row">
                                    <span class="feature-name">Role: <strong>${{roleName}}</strong></span>
                                    <span class="feature-permission none">No specific space permissions defined</span>
                                </div>
                            </div>
                        </div>
                    `;
                }}
            }}
        }}
        
        // Clear filter
        function clearFilter() {{
            selectedRole = null;
            
            // Reset pill states
            document.querySelectorAll('.role-pill').forEach(pill => {{
                pill.classList.remove('active');
            }});
            
            // Show all rows and cards
            document.querySelectorAll('.filtered-out').forEach(element => {{
                element.classList.remove('filtered-out');
                element.style.display = ''; // Reset display property
            }});
            
            // Hide filter info
            document.getElementById('filter-info-kibana').style.display = 'none';
            document.getElementById('filter-info-cluster').style.display = 'none';
            document.getElementById('filter-info-detailed').style.display = 'none';
            
            // Hide clear button
            document.getElementById('clear-btn').style.display = 'none';
            
            // Reset search box
            document.querySelector('.search-box').value = '';
            
            // Reset filtered roles count
            document.getElementById('filtered-roles').textContent = roleData.length.toString();
            
            // Show all role pills
            document.querySelectorAll('.role-pill').forEach(pill => {{
                pill.style.display = 'block';
            }});
            
            // Reset space cards
            const spaceContainer = document.getElementById('space-cards');
            spaceContainer.innerHTML = '<div class="no-spaces">Select a role above to see space-specific permissions</div>';
        }}
        
        // Search roles
        function searchRoles(searchTerm) {{
            const term = searchTerm.toLowerCase();
            document.querySelectorAll('.role-pill').forEach(pill => {{
                const roleName = pill.getAttribute('data-role').toLowerCase();
                if (roleName.includes(term)) {{
                    pill.style.display = 'block';
                }} else {{
                    pill.style.display = 'none';
                }}
            }});
        }}
        
        // Switch tabs
        function switchTab(tabId) {{
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(content => {{
                content.classList.remove('active');
            }});
            
            // Remove active class from all tab buttons
            document.querySelectorAll('.tab-btn').forEach(btn => {{
                btn.classList.remove('active');
            }});
            
            // Show selected tab content
            document.getElementById(tabId).classList.add('active');
            
            // Activate clicked tab button
            event.target.classList.add('active');
        }}
        
        // Toggle role details in detailed view
        function toggleRoleDetails(roleName) {{
            const detailsDiv = document.getElementById(`details-${{roleName}}`);
            const toggleText = document.getElementById(`toggle-text-${{roleName}}`);
            
            if (detailsDiv.style.display === 'none') {{
                detailsDiv.style.display = 'block';
                toggleText.textContent = '▲ Hide Details';
            }} else {{
                detailsDiv.style.display = 'none';
                toggleText.textContent = '▼ Show Details';
            }}
        }}
        
        // Toggle raw privileges display
        function toggleRawPrivileges(elementId) {{
            const element = document.getElementById(`raw-${{elementId}}`);
            if (element.style.display === 'none') {{
                element.style.display = 'block';
            }} else {{
                element.style.display = 'none';
            }}
        }}
        
        // Toggle all raw privileges for a role
        function toggleAllRawPrivileges(roleName) {{
            const element = document.getElementById(`all-raw-${{roleName}}`);
            const toggleBtn = document.getElementById(`raw-toggle-${{roleName}}`);
            
            if (element.style.display === 'none') {{
                element.style.display = 'block';
                toggleBtn.textContent = 'Hide All';
            }} else {{
                element.style.display = 'none';
                toggleBtn.textContent = 'Show All';
            }}
        }}
        
        // Initialize on page load
        window.addEventListener('load', () => {{
            initializeRolePills();
        }});
        
        // Toggle cluster privileges display
        function toggleClusterPrivileges(roleName) {{
            const hiddenDiv = document.getElementById(`cluster-hidden-${{roleName}}`);
            const toggleBtn = document.getElementById(`toggle-btn-${{roleName}}`);
            
            if (hiddenDiv.style.display === 'none') {{
                hiddenDiv.style.display = 'flex';
                toggleBtn.textContent = 'Show less';
                toggleBtn.style.backgroundColor = '#28a745';
            }} else {{
                hiddenDiv.style.display = 'none';
                const totalPrivs = hiddenDiv.querySelectorAll('.es-privilege').length;
                const shownPrivs = 3;
                toggleBtn.textContent = `+${{totalPrivs - shownPrivs}} more`;
                toggleBtn.style.backgroundColor = '#6c757d';
            }}
        }}
        
        // Toggle index detail
        function toggleIndexDetail(elementId) {{
            const element = document.getElementById(elementId);
            if (element.style.display === 'none' || element.style.display === '') {{
                element.style.display = 'block';
            }} else {{
                element.style.display = 'none';
            }}
        }}
    </script>
</body>
</html>"""
        
        return html_template
    
    def create_csv_export(self, file_path: str):
        """Create enhanced CSV export of role permissions with detailed breakdown"""
        import csv
        
        roles = self.analysis['roles']
        features = self.analysis['kibana_features']
        
        with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Enhanced header row with detailed columns
            header = ['Role', 'Global_Privileges', 'Raw_Privilege_Count'] + [f'{feature}_Level' for feature in features] + [f'{feature}_Raw_Privileges' for feature in features]
            writer.writerow(header)
            
            # Data rows
            for role_name, role_data in roles.items():
                perms = role_data['kibana_permissions']
                detailed_perms = role_data.get('detailed_permissions', {})
                
                # Basic info
                row = [role_name]
                
                # Global privileges
                global_privs = detailed_perms.get('global_privileges', [])
                row.append('; '.join(global_privs) if global_privs else 'None')
                
                # Raw privilege count
                raw_privs = detailed_perms.get('raw_privileges', [])
                row.append(len(raw_privs))
                
                # Feature levels
                for feature in features:
                    row.append(perms.get(feature, 'NONE'))
                
                # Feature raw privileges
                features_data = detailed_perms.get('features', {})
                for feature in features:
                    feature_data = features_data.get(feature, {})
                    feature_privs = feature_data.get('privileges', [])
                    row.append('; '.join(feature_privs) if feature_privs else 'None')
                
                writer.writerow(row)

def main():
    root = tk.Tk()
    app = KibanaMapperGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
