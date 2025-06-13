#!/usr/bin/env python3
"""
Elastic Role Permission Mapper
A GUI tool to analyze and visualize Elastic Cloud Kibana permissions with detailed sub-feature breakdown, local users, and space selection
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import webbrowser
import tempfile
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
import threading
import re

try:
    from elasticsearch import Elasticsearch
    from elasticsearch.exceptions import AuthenticationException as AuthenticationError
    from elasticsearch.exceptions import ConnectionError as ESConnectionError, NotFoundError
except ImportError as e:
    print(f"Please install elasticsearch 8.x: pip install 'elasticsearch>=8.0,<9.0'")
    print(f"Import error details: {e}")
    exit(1)

class KibanaRoleMapper:
    def __init__(self):
        self.es = None
        self.roles_data = {}
        self.mappings_data = {}
        self.users_data = {}
        self.connected = False

    def connect(self, connection_params: Dict) -> bool:
        """Connect to Elasticsearch (Cloud or Local) - optimized for ES 8.x"""
        try:
            connection_type = connection_params.get('type', 'cloud')

            if connection_type == 'cloud':
                cloud_id = connection_params.get('cloud_id')
                api_key_str = connection_params.get('api_key')
                if not cloud_id or not api_key_str:
                    raise ValueError("Cloud ID and API Key are required for Elastic Cloud connection.")

                if ':' in api_key_str:
                    api_key_id, api_key_secret = api_key_str.split(':', 1)
                    auth_param = (api_key_id, api_key_secret)
                else:
                    auth_param = api_key_str # Assumed base64 encoded

                self.es = Elasticsearch(
                    cloud_id=cloud_id,
                    api_key=auth_param,
                    request_timeout=30
                )
            elif connection_type == 'local':
                hosts = connection_params.get('hosts')
                if not hosts:
                    raise ValueError("Host(s) are required for local Elasticsearch connection.")

                auth_type = connection_params.get('auth_type', 'none')
                auth_param = None
                
                if auth_type == 'api_key':
                    api_key_str = connection_params.get('api_key')
                    if not api_key_str:
                        raise ValueError("API Key is required for local API key authentication.")
                    if ':' in api_key_str:
                        api_key_id, api_key_secret = api_key_str.split(':', 1)
                        auth_param = (api_key_id, api_key_secret)
                    else:
                        # For local, it might just be the key itself if not id:secret
                        auth_param = api_key_str
                    self.es = Elasticsearch(hosts=hosts, api_key=auth_param, request_timeout=30)

                elif auth_type == 'basic_auth':
                    username = connection_params.get('username')
                    password = connection_params.get('password')
                    if not username: # Password can be empty
                        raise ValueError("Username is required for basic authentication.")
                    auth_param = (username, password)
                    self.es = Elasticsearch(hosts=hosts, basic_auth=auth_param, request_timeout=30)
                
                else: # 'none' or unrecognized
                    self.es = Elasticsearch(hosts=hosts, request_timeout=30)
            else:
                raise ValueError(f"Unsupported connection type: {connection_type}")

            # Test connection
            info = self.es.info()
            self.connected = True
            return True

        except AuthenticationError as e:
            raise Exception(f"Authentication failed. Check your credentials. Details: {str(e)}")
        except ESConnectionError as e:
            raise Exception(f"Connection failed. Check your connection parameters (Cloud ID or Host). Details: {str(e)}")
        except ValueError as e: # For parameter validation
            raise Exception(str(e))
        except Exception as e:
            raise Exception(f"Connection error: {str(e)}")

    def fetch_data(self) -> Dict:
        """Fetch roles, mappings, and users from Elasticsearch"""
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
            
            # Get users (native realm)
            try:
                users_response = self.es.security.get_user()
                self.users_data = users_response
                print(f"Fetched {len(self.users_data)} users from native realm")
            except (NotFoundError) as user_error:
                print(f"Warning: Could not fetch users (may not have permission or native realm not enabled): {user_error}")
                self.users_data = {}
            except Exception as user_error:
                print(f"Warning: Error fetching users: {user_error}")
                self.users_data = {}
            
            # Get cluster info
            cluster_info = self.es.info()
            
            return {
                'roles': self.roles_data,
                'mappings': self.mappings_data,
                'users': self.users_data,
                'cluster_info': cluster_info,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            raise Exception(f"Failed to fetch data: {str(e)}")
    
    def merge_permission_levels(self, current_level: str, new_level: str) -> str:
        """Merge two permission levels, taking the higher one"""
        level_hierarchy = {
            'NONE': 0,
            'CUSTOM': 1,
            'READ': 2,
            'WRITE': 3,
            'ADMIN': 4
        }
        
        current_rank = level_hierarchy.get(current_level, 0)
        new_rank = level_hierarchy.get(new_level, 0)
        
        if new_rank > current_rank:
            return new_level
        return current_level
    
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
    
    def analyze_users(self, users_data: Dict, roles_data: Dict) -> Dict:
        """Analyze user data and relationships with roles"""
        if not users_data:
            return {
                'total_users': 0,
                'active_users': 0,
                'inactive_users': 0,
                'users_by_role_count': {},
                'role_user_mapping': {},
                'users_without_roles': [],
                'user_details': {},
                'available': False
            }
        
        user_analysis = {
            'total_users': len(users_data),
            'active_users': 0,
            'inactive_users': 0,
            'users_by_role_count': {0: 0, 1: 0, 'multiple': 0},
            'role_user_mapping': {},  # role_name -> [users]
            'users_without_roles': [],
            'user_details': {},
            'available': True
        }
        
        # Initialize role user mapping
        for role_name in roles_data.keys():
            user_analysis['role_user_mapping'][role_name] = []
        
        # Analyze each user
        for username, user_data in users_data.items():
            enabled = user_data.get('enabled', True)
            roles = user_data.get('roles', [])
            full_name = user_data.get('full_name', '')
            email = user_data.get('email', '')
            metadata = user_data.get('metadata', {})
            
            # Count active/inactive
            if enabled:
                user_analysis['active_users'] += 1
            else:
                user_analysis['inactive_users'] += 1
            
            # Analyze role assignments
            role_count = len(roles)
            if role_count == 0:
                user_analysis['users_by_role_count'][0] += 1
                user_analysis['users_without_roles'].append(username)
            elif role_count == 1:
                user_analysis['users_by_role_count'][1] += 1
            else:
                user_analysis['users_by_role_count']['multiple'] += 1
            
            # Map users to roles
            for role in roles:
                if role in user_analysis['role_user_mapping']:
                    user_analysis['role_user_mapping'][role].append(username)
                else:
                    # Role assigned to user but not found in roles (might be built-in or external)
                    user_analysis['role_user_mapping'][role] = [username]
            
            # Store user details
            user_analysis['user_details'][username] = {
                'enabled': enabled,
                'roles': roles,
                'full_name': full_name,
                'email': email,
                'metadata': metadata,
                'role_count': role_count
            }
        
        return user_analysis
    
    def analyze_permissions(self, data: Dict) -> Dict:
        """Analyze role permissions and create structured output with detailed sub-features, users, and proper space handling"""
        roles = data['roles']
        mappings = data['mappings']
        users = data['users']
        
        # Kibana features to check
        kibana_features = [
            'discover', 'dashboard', 'visualize', 'canvas', 'maps',
            'ml', 'apm', 'uptime', 'logs', 'infrastructure',
            'siem', 'dev_tools', 'advancedSettings', 'indexPatterns',
            'savedObjectsManagement', 'graph', 'monitoring', 'fleet',
            'osquery', 'security', 'alerts', 'cases', 'enterpriseSearch'
        ]
        
        # Collect all unique spaces across all roles
        all_spaces_global = set()
        
        # Analyze each role
        role_analysis = {}
        for role_name, role_data in roles.items():
            analysis = {
                'kibana_permissions': {},
                'detailed_permissions': {},
                'elasticsearch_permissions': {},
                'spaces': [],
                'space_permissions': {},
                'all_spaces': set()
            }
            
            # Check Kibana application privileges - ENHANCED FOR PROPER SPACE HANDLING
            applications = role_data.get('applications', [])
            
            # Initialize space permissions tracking
            space_permissions = {}
            all_spaces_for_role = set()
            
            # Process each application entry separately
            for app in applications:
                if app.get('application') == 'kibana-.kibana':
                    privileges = app.get('privileges', [])
                    spaces = app.get('resources', ['*'])
                    
                    # Parse detailed privileges for this application entry
                    detailed_perms = self.parse_detailed_privileges(privileges)
                    
                    # Apply these privileges to each space in this application entry
                    for space in spaces:
                        space_name = space.replace('space:', '') if space != '*' else 'Default'
                        all_spaces_for_role.add(space_name)
                        all_spaces_global.add(space_name)
                        
                        # Initialize space permissions if not exists
                        if space_name not in space_permissions:
                            space_permissions[space_name] = {}
                            for feature in kibana_features:
                                space_permissions[space_name][feature] = 'NONE'
                        
                        # Merge permissions for this space
                        for feature in kibana_features:
                            feature_data = detailed_perms['features'].get(feature, {})
                            current_level = space_permissions[space_name][feature]
                            new_level = feature_data.get('level', 'NONE')
                            space_permissions[space_name][feature] = self.merge_permission_levels(current_level, new_level)
                    
                    # Store the detailed permissions from the first (or most comprehensive) application entry
                    if not analysis['detailed_permissions']:
                        analysis['detailed_permissions'] = detailed_perms
                    else:
                        # Merge with existing detailed permissions
                        existing_detailed = analysis['detailed_permissions']
                        for feature in kibana_features:
                            existing_level = existing_detailed['features'].get(feature, {}).get('level', 'NONE')
                            new_level = detailed_perms['features'].get(feature, {}).get('level', 'NONE')
                            merged_level = self.merge_permission_levels(existing_level, new_level)
                            existing_detailed['features'][feature]['level'] = merged_level
            
            # Store space information
            analysis['spaces'] = sorted(list(all_spaces_for_role))
            analysis['all_spaces'] = all_spaces_for_role
            analysis['space_permissions'] = space_permissions
            
            # Create global permissions view (highest permission across all spaces)
            global_permissions = {}
            for feature in kibana_features:
                highest_level = 'NONE'
                for space_name, space_perms in space_permissions.items():
                    space_level = space_perms.get(feature, 'NONE')
                    highest_level = self.merge_permission_levels(highest_level, space_level)
                global_permissions[feature] = highest_level
            
            analysis['kibana_permissions'] = global_permissions
            
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
        
        # Analyze users
        user_analysis = self.analyze_users(users, roles)
        
        return {
            'roles': role_analysis,
            'saml_mappings': saml_analysis,
            'users': user_analysis,
            'kibana_features': kibana_features,
            'all_spaces': sorted(list(all_spaces_global)),  # NEW: All unique spaces
            'stats': {
                'total_roles': len(roles),
                'total_mappings': len(mappings),
                'total_users': user_analysis['total_users'],
                'total_features': len(kibana_features),
                'total_spaces': len(all_spaces_global)  # NEW: Total unique spaces
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

        # Connection type and details
        self.connection_type_var = tk.StringVar(value="cloud")
        self.cloud_id_var = tk.StringVar()
        self.api_key_var = tk.StringVar() # Used for both cloud and local API key auth

        self.local_hosts_var = tk.StringVar(value="http://localhost:9200")
        self.local_auth_type_var = tk.StringVar(value="none")
        # self.local_api_key_var = tk.StringVar() # Re-use self.api_key_var
        self.local_username_var = tk.StringVar()
        self.local_password_var = tk.StringVar()
        
        self.setup_ui()

    def _toggle_connection_fields(self, *args):
        conn_type = self.connection_type_var.get()
        
        # Cloud fields
        self.cloud_id_label.grid_remove()
        self.cloud_id_entry.grid_remove()
        self.cloud_api_key_label.grid_remove()
        self.cloud_api_key_entry.grid_remove()

        # Local fields
        self.local_hosts_label.grid_remove()
        self.local_hosts_entry.grid_remove()
        self.local_auth_label.grid_remove()
        self.local_auth_frame.grid_remove() # Frame containing auth radio buttons
        self.local_api_key_label.grid_remove()
        self.local_api_key_entry.grid_remove()
        self.local_basic_auth_frame.grid_remove() # Frame for username/password

        if conn_type == "cloud":
            self.conn_frame.config(text="Elastic Cloud Connection")
            self.cloud_id_label.grid()
            self.cloud_id_entry.grid()
            self.cloud_api_key_label.grid()
            self.cloud_api_key_entry.grid()
        elif conn_type == "local":
            self.conn_frame.config(text="Local Elasticsearch Connection")
            self.local_hosts_label.grid()
            self.local_hosts_entry.grid()
            self.local_auth_label.grid()
            self.local_auth_frame.grid()
            self._toggle_local_auth_fields() # Further toggle based on auth type

    def _toggle_local_auth_fields(self, *args):
        auth_type = self.local_auth_type_var.get()

        self.local_api_key_label.grid_remove()
        self.local_api_key_entry.grid_remove()
        self.local_basic_auth_frame.grid_remove()

        if auth_type == "api_key":
            self.local_api_key_label.grid()
            self.local_api_key_entry.grid()
        elif auth_type == "basic_auth":
            self.local_basic_auth_frame.grid()
        
    def setup_ui(self):
        """Setup the GUI"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Connection frame (dynamically titled)
        self.conn_frame = ttk.LabelFrame(main_frame, text="Elastic Connection", padding="10")
        self.conn_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Connection Type Selection
        conn_type_frame = ttk.Frame(self.conn_frame)
        conn_type_frame.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0,10))
        ttk.Label(conn_type_frame, text="Connection Type:").pack(side=tk.LEFT, padx=(0,5))
        ttk.Radiobutton(conn_type_frame, text="Elastic Cloud", variable=self.connection_type_var, value="cloud", command=self._toggle_connection_fields).pack(side=tk.LEFT)
        ttk.Radiobutton(conn_type_frame, text="Local Instance", variable=self.connection_type_var, value="local", command=self._toggle_connection_fields).pack(side=tk.LEFT, padx=(10,0))

        # --- Cloud Connection Fields ---
        self.cloud_id_label = ttk.Label(self.conn_frame, text="Cloud ID:")
        self.cloud_id_label.grid(row=1, column=0, sticky=tk.W, pady=(0, 5))
        self.cloud_id_entry = ttk.Entry(self.conn_frame, textvariable=self.cloud_id_var, width=60)
        self.cloud_id_entry.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.cloud_api_key_label = ttk.Label(self.conn_frame, text="API Key (id:secret or base64):")
        self.cloud_api_key_label.grid(row=3, column=0, sticky=tk.W, pady=(0, 5))
        self.cloud_api_key_entry = ttk.Entry(self.conn_frame, textvariable=self.api_key_var, width=60, show="*")
        self.cloud_api_key_entry.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        # --- Local Connection Fields ---
        self.local_hosts_label = ttk.Label(self.conn_frame, text="Host(s) (comma-separated, e.g., http://localhost:9200):")
        self.local_hosts_label.grid(row=1, column=0, sticky=tk.W, pady=(0, 5))
        self.local_hosts_entry = ttk.Entry(self.conn_frame, textvariable=self.local_hosts_var, width=60)
        self.local_hosts_entry.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        self.local_auth_label = ttk.Label(self.conn_frame, text="Authentication:")
        self.local_auth_label.grid(row=3, column=0, sticky=tk.W, pady=(5,0))
        
        self.local_auth_frame = ttk.Frame(self.conn_frame)
        self.local_auth_frame.grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=(0,10))
        ttk.Radiobutton(self.local_auth_frame, text="None", variable=self.local_auth_type_var, value="none", command=self._toggle_local_auth_fields).pack(side=tk.LEFT)
        ttk.Radiobutton(self.local_auth_frame, text="API Key", variable=self.local_auth_type_var, value="api_key", command=self._toggle_local_auth_fields).pack(side=tk.LEFT, padx=(10,0))
        ttk.Radiobutton(self.local_auth_frame, text="Basic Auth", variable=self.local_auth_type_var, value="basic_auth", command=self._toggle_local_auth_fields).pack(side=tk.LEFT, padx=(10,0))

        # Local API Key (reuses self.api_key_var)
        self.local_api_key_label = ttk.Label(self.conn_frame, text="API Key (id:secret or base64):")
        self.local_api_key_label.grid(row=5, column=0, sticky=tk.W, pady=(0, 5))
        self.local_api_key_entry = ttk.Entry(self.conn_frame, textvariable=self.api_key_var, width=60, show="*") # Reuses api_key_var
        self.local_api_key_entry.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        # Local Basic Auth (Username/Password)
        self.local_basic_auth_frame = ttk.Frame(self.conn_frame)
        self.local_basic_auth_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0,10)) # Spans 2 columns
        
        ttk.Label(self.local_basic_auth_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=(0,5))
        local_username_entry = ttk.Entry(self.local_basic_auth_frame, textvariable=self.local_username_var, width=28)
        local_username_entry.grid(row=0, column=1, sticky=tk.W, pady=(0,5), padx=(0,10))
        
        ttk.Label(self.local_basic_auth_frame, text="Password:").grid(row=0, column=2, sticky=tk.W, pady=(0,5))
        local_password_entry = ttk.Entry(self.local_basic_auth_frame, textvariable=self.local_password_var, width=28, show="*")
        local_password_entry.grid(row=0, column=3, sticky=tk.W, pady=(0,5))
        
        # Common fields (ES Version, Connect Button, Status)
        # Adjust row numbers for these common fields
        current_row = 7 # Next available row after local auth specific fields
        
        ttk.Label(self.conn_frame, text="Target: Elasticsearch 8.x clusters").grid(row=current_row, column=0, sticky=tk.W, pady=(10, 5))
        current_row += 1
        version_note = ttk.Label(self.conn_frame, text="(Enhanced with detailed sub-feature permission analysis + Local Users + Space Selection)", font=('TkDefaultFont', 8))
        version_note.grid(row=current_row, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))
        current_row += 1
        
        self.connect_btn = ttk.Button(self.conn_frame, text="Connect", command=self.connect_to_elastic)
        self.connect_btn.grid(row=current_row, column=0, sticky=tk.W)
        
        self.status_var = tk.StringVar(value="Not connected")
        self.status_label = ttk.Label(self.conn_frame, textvariable=self.status_var)
        self.status_label.grid(row=current_row, column=1, sticky=tk.E) # Ensure it's in the second column of conn_frame
        
        # Initial toggle
        self._toggle_connection_fields()

        # Actions frame
        actions_frame = ttk.LabelFrame(main_frame, text="Actions", padding="10")
        actions_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Fetch data button
        self.fetch_btn = ttk.Button(actions_frame, text="Fetch Role & User Data", 
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
        self.conn_frame.columnconfigure(1, weight=1) # Allow status label to expand if needed
        
    def connect_to_elastic(self):
        """Connect to Elastic Cloud or Local Instance"""
        connection_type = self.connection_type_var.get()
        params = {'type': connection_type}
        
        try:
            if connection_type == "cloud":
                params['cloud_id'] = self.cloud_id_var.get().strip()
                params['api_key'] = self.api_key_var.get().strip()
                if not params['cloud_id'] or not params['api_key']:
                    messagebox.showerror("Error", "Please enter both Cloud ID and API Key for Elastic Cloud.")
                    return
            elif connection_type == "local":
                hosts_str = self.local_hosts_var.get().strip()
                if not hosts_str:
                    messagebox.showerror("Error", "Please enter Host(s) for local connection.")
                    return
                params['hosts'] = [h.strip() for h in hosts_str.split(',')]
                
                params['auth_type'] = self.local_auth_type_var.get()
                if params['auth_type'] == "api_key":
                    params['api_key'] = self.api_key_var.get().strip() # Reuses api_key_var
                    if not params['api_key']:
                        messagebox.showerror("Error", "Please enter API Key for local connection.")
                        return
                elif params['auth_type'] == "basic_auth":
                    params['username'] = self.local_username_var.get().strip()
                    params['password'] = self.local_password_var.get().strip() # Password can be empty
                    if not params['username']:
                        messagebox.showerror("Error", "Please enter Username for basic authentication.")
                        return
            else:
                messagebox.showerror("Error", "Invalid connection type selected.")
                return

            def connect_thread():
                try:
                    self.status_var.set("Connecting...")
                    self.connect_btn.config(state=tk.DISABLED)
                    
                    self.mapper.connect(params) # Pass the dictionary
                    
                    self.status_var.set(f"Connected successfully ({connection_type.capitalize()})")
                    self.fetch_btn.config(state=tk.NORMAL)
                    self.results_text.insert(tk.END, f"✅ Connected to Elasticsearch ({connection_type.capitalize()}) successfully\n")
                    
                except Exception as e:
                    self.status_var.set("Connection failed")
                    messagebox.showerror("Connection Error", str(e))
                    
                finally:
                    self.connect_btn.config(state=tk.NORMAL)
            
            threading.Thread(target=connect_thread, daemon=True).start()

        except Exception as e: # Catch any pre-thread errors (e.g., validation)
             messagebox.showerror("Configuration Error", str(e))
    
    def fetch_data(self):
        """Fetch role, mapping, and user data"""
        def fetch_thread():
            try:
                self.results_text.insert(tk.END, "\n🔄 Fetching roles, mappings, and local users with detailed analysis and space handling...\n")
                self.fetch_btn.config(state=tk.DISABLED)
                
                self.data = self.mapper.fetch_data()
                self.analysis = self.mapper.analyze_permissions(self.data)
                
                # Display summary
                stats = self.analysis['stats']
                user_info = self.analysis['users']
                all_spaces = self.analysis.get('all_spaces', [])
                
                summary = f"""
📊 Enhanced Data Summary:
• Total Roles: {stats['total_roles']}
• SAML Mappings: {stats['total_mappings']}
• Local Users: {stats['total_users']} {'(Active: ' + str(user_info['active_users']) + ', Inactive: ' + str(user_info['inactive_users']) + ')' if user_info['available'] else '(Not available - check permissions)'}
• Kibana Features: {stats['total_features']}
• Kibana Spaces: {stats.get('total_spaces', 0)} ({', '.join(all_spaces[:5])}{'...' if len(all_spaces) > 5 else ''})

✨ Enhancement: Now includes detailed sub-feature permissions + Local Users analysis + Space Selection!

Roles found:
"""
                for role_name in self.analysis['roles'].keys():
                    summary += f"  • {role_name}\n"
                
                if all_spaces:
                    summary += f"\nKibana Spaces found ({len(all_spaces)} total):\n"
                    for space in all_spaces[:10]:  # Show first 10 spaces
                        summary += f"  • {space}\n"
                    if len(all_spaces) > 10:
                        summary += f"  ... and {len(all_spaces) - 10} more spaces\n"
                
                if self.analysis['saml_mappings']:
                    summary += "\nSAML Mappings:\n"
                    for mapping_name in self.analysis['saml_mappings'].keys():
                        summary += f"  • {mapping_name}\n"
                
                if user_info['available'] and user_info['total_users'] > 0:
                    summary += f"\nLocal Users ({user_info['total_users']} total):\n"
                    # Show first few users
                    user_list = list(user_info['user_details'].keys())[:5]
                    for username in user_list:
                        user_detail = user_info['user_details'][username]
                        status = "✅" if user_detail['enabled'] else "❌"
                        role_count = user_detail['role_count']
                        summary += f"  • {username} {status} ({role_count} roles)\n"
                    if len(user_info['user_details']) > 5:
                        summary += f"  ... and {len(user_info['user_details']) - 5} more users\n"
                elif not user_info['available']:
                    summary += "\n⚠️  Local users not available (may need different permissions or native realm not enabled)\n"
                
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
            self.results_text.insert(tk.END, "\n📄 Enhanced HTML report with detailed permissions, local users, and space selection opened in browser\n")
            
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
                title="Save Enhanced Kibana Permission Report with Users and Spaces"
            )
            
            if file_path:
                # Add timestamp to filename if user didn't specify one
                if not file_path.endswith('.html'):
                    file_path += '.html'
                    
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                messagebox.showinfo("Success", f"Enhanced report with users and spaces saved to {file_path}")
                self.results_text.insert(tk.END, f"\n📄 Enhanced HTML report with users and spaces saved to {file_path}\n")
                
        except Exception as e:
            messagebox.showerror("Report Error", f"Failed to generate report: {str(e)}")
    
    def export_csv(self):
        """Export role permissions and users to CSV"""
        if not self.analysis:
            messagebox.showerror("Error", "No data available. Please fetch data first.")
            return
        
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                title="Export Enhanced Kibana Permissions, Users, and Spaces to CSV"
            )
            
            if file_path:
                # Add timestamp to filename if user didn't specify one
                if not file_path.endswith('.csv'):
                    file_path += '.csv'
                    
                self.create_csv_export(file_path)
                messagebox.showinfo("Success", f"Enhanced CSV with users and spaces exported to {file_path}")
                self.results_text.insert(tk.END, f"\n📊 Enhanced CSV with users and spaces exported to {file_path}\n")
                
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export CSV: {str(e)}")
    
    def create_html_report(self) -> str:
        """Create enhanced HTML report content with detailed sub-feature permissions, local users, and space selection"""
        roles = self.analysis['roles']
        mappings = self.analysis['saml_mappings']
        users_analysis = self.analysis['users']
        features = self.analysis['kibana_features']
        all_spaces = self.analysis.get('all_spaces', [])
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
        
        # Create space-specific permission matrix
        space_matrix_html = ""
        if all_spaces:
            for space_name in all_spaces:
                safe_space_name = str(space_name).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
                space_rows = ""
                
                for role_name, role_data in roles.items():
                    space_perms = role_data.get('space_permissions', {}).get(space_name, {})
                    if space_perms:  # Only show roles that have permissions in this space
                        safe_role_name = str(role_name).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
                        row = f"<tr><td><strong>{safe_role_name}</strong></td>"
                        
                        for feature in features:
                            perm_level = space_perms.get(feature, 'NONE')
                            css_class = f"permission-{perm_level.lower()}"
                            row += f'<td class="{css_class}">{perm_level}</td>'
                        
                        row += "</tr>"
                        space_rows += row
                
                if space_rows:  # Only create matrix if there are permissions for this space
                    feature_headers = ''.join([f'<th>{str(feature).title()}</th>' for feature in features])
                    space_matrix_html += f'''
                    <div class="space-matrix" id="space-matrix-{safe_space_name}" style="display: none;">
                        <h4>🏠 Permissions in Space: {safe_space_name}</h4>
                        <table class="matrix-table">
                            <thead>
                                <tr>
                                    <th class="role-header">Role</th>
                                    {feature_headers}
                                </tr>
                            </thead>
                            <tbody>
                                {space_rows}
                            </tbody>
                        </table>
                    </div>
                    '''
        
        # Create detailed permissions section (existing but enhanced)
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
                
                # Space information
                role_spaces = role_data.get('spaces', [])
                space_info = ""
                if role_spaces:
                    space_info = f'<div class="space-info"><strong>Applies to spaces:</strong> {", ".join(role_spaces)}</div>'
                
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
                        
                        show_raw_btn = f'<button class="show-raw" onclick="toggleRawPrivileges(\'{safe_role_name}-{feature}\')">Show Raw</button>' if privileges else ''
                        
                        feature_breakdown += f'''
                        <div class="detailed-feature-card">
                            <div class="feature-header">
                                <span class="feature-name">{feature_display}</span>
                                <span class="feature-level {level_class}">{level}</span>
                                {show_raw_btn}
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
                
                # Create content variables for this role
                feature_breakdown_content = feature_breakdown if feature_breakdown else '<span class="no-features">No feature-specific permissions</span>'
                global_section = f'<div class="global-section"><strong>Global Privileges:</strong> {global_badges}</div>' if global_badges else ''
                other_section = f'<div class="other-section"><strong>Other Privileges:</strong> {other_badges}</div>' if other_badges else ''
                
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
                        {space_info}
                        {global_section}
                        
                        <div class="features-section">
                            <strong>Feature Permissions:</strong>
                            <div class="feature-grid">
                                {feature_breakdown_content}
                            </div>
                        </div>
                        
                        {other_section}
                        
                        <div class="raw-section">
                            <strong>All Raw Privileges:</strong>
                            <button class="show-all-raw" onclick="toggleAllRawPrivileges('{safe_role_name}')">
                                <span id="raw-toggle-{safe_role_name}">Show All</span>
                            </button>
                            <div class="all-raw-privileges" id="all-raw-{safe_role_name}" style="display: none;">
                                {''.join([f'<code class="privilege-code">{priv}</code>' for priv in raw_privs])}
                            </div>
                        </div>
                    </div>
                </div>
                '''
        
        # Create local users section (existing)
        users_html = ""
        user_role_matrix_html = ""
        user_stats_html = ""
        
        if users_analysis['available'] and users_analysis['total_users'] > 0:
            user_details = users_analysis['user_details']
            role_user_mapping = users_analysis['role_user_mapping']
            
            # User statistics
            active_users = users_analysis['active_users']
            inactive_users = users_analysis['inactive_users']
            users_by_role_count = users_analysis['users_by_role_count']
            users_without_roles = users_analysis['users_without_roles']
            
            user_stats_html = f'''
            <div class="user-stats">
                <div class="user-stat-cards">
                    <div class="user-stat-card active clickable" onclick="filterUsersByCategory('active')" data-category="active">
                        <div class="stat-number">{active_users}</div>
                        <div class="stat-label">Active Users</div>
                    </div>
                    <div class="user-stat-card inactive clickable" onclick="filterUsersByCategory('inactive')" data-category="inactive">
                        <div class="stat-number">{inactive_users}</div>
                        <div class="stat-label">Inactive Users</div>
                    </div>
                    <div class="user-stat-card no-roles clickable" onclick="filterUsersByCategory('no-roles')" data-category="no-roles">
                        <div class="stat-number">{users_by_role_count.get(0, 0)}</div>
                        <div class="stat-label">Users Without Roles</div>
                    </div>
                    <div class="user-stat-card multiple-roles clickable" onclick="filterUsersByCategory('multiple-roles')" data-category="multiple-roles">
                        <div class="stat-number">{users_by_role_count.get('multiple', 0)}</div>
                        <div class="stat-label">Users with Multiple Roles</div>
                    </div>
                </div>
                <div id="user-filter-info" class="filter-info" style="display: none; margin-top: 15px;">
                    Showing: <strong id="user-filter-text"></strong>
                    <button class="clear-filter" onclick="clearUserFilter()" style="margin-left: 10px;">Clear Filter</button>
                </div>
            </div>
            '''
            
            # User cards
            for username, user_data in user_details.items():
                safe_username = str(username).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
                safe_full_name = str(user_data.get('full_name', '')).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
                safe_email = str(user_data.get('email', '')).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
                
                enabled = user_data['enabled']
                user_roles = user_data['roles']
                role_count = user_data['role_count']
                
                # Create role badges
                role_badges = ""
                for role in user_roles:
                    safe_role = str(role).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
                    # Check if this is a known role (in our roles data) or external/built-in
                    role_class = "role-badge known" if role in roles else "role-badge external"
                    role_badges += f'<span class="{role_class}">{safe_role}</span> '
                
                if not role_badges:
                    role_badges = '<span class="role-badge no-roles">No roles assigned</span>'
                
                # User status
                status_class = "enabled" if enabled else "disabled"
                status_text = "✅ Active" if enabled else "❌ Inactive"
                
                full_name_div = f'<div class="user-full-name">{safe_full_name}</div>' if safe_full_name else ''
                email_div = f'<div class="user-email">{safe_email}</div>' if safe_email else ''
                
                users_html += f'''
                <div class="user-card {status_class}">
                    <div class="user-header">
                        <div class="user-info">
                            <h4>{safe_username}</h4>
                            {full_name_div}
                            {email_div}
                        </div>
                        <div class="user-status">
                            <span class="status-badge {status_class}">{status_text}</span>
                            <span class="role-count">{role_count} roles</span>
                        </div>
                    </div>
                    <div class="user-roles">
                        <strong>Assigned Roles:</strong>
                        <div class="role-badges">
                            {role_badges}
                        </div>
                    </div>
                </div>
                '''
            
            # User-Role Matrix
            if user_details and roles:
                matrix_header = '<th class="user-header">User</th>'
                for role_name in sorted(roles.keys()):
                    safe_role_name = str(role_name).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
                    matrix_header += f'<th class="role-header-small">{safe_role_name}</th>'
                
                matrix_body = ""
                for username in sorted(user_details.keys()):
                    safe_username = str(username).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
                    user_data = user_details[username]
                    user_roles = user_data['roles']
                    enabled = user_data['enabled']
                    
                    row_class = "enabled-user" if enabled else "disabled-user"
                    row = f'<tr class="{row_class}"><td><strong>{safe_username}</strong></td>'
                    
                    for role_name in sorted(roles.keys()):
                        has_role = role_name in user_roles
                        cell_class = "has-role" if has_role else "no-role"
                        cell_content = "✅" if has_role else ""
                        row += f'<td class="{cell_class}">{cell_content}</td>'
                    
                    row += "</tr>"
                    matrix_body += row
                
                user_role_matrix_html = f'''
                <div class="user-role-matrix">
                    <table class="matrix-table">
                        <thead>
                            <tr>{matrix_header}</tr>
                        </thead>
                        <tbody id="user-matrix-tbody">
                            {matrix_body}
                        </tbody>
                    </table>
                </div>
                '''
        
        elif not users_analysis['available']:
            users_html = '''
            <div class="no-users-available">
                <div class="info-box">
                    <h3>🔒 Local Users Not Available</h3>
                    <p>Local users could not be retrieved. This might be due to:</p>
                    <ul>
                        <li>Insufficient permissions to access the user API</li>
                        <li>Native realm not enabled on this cluster</li>
                        <li>Users managed by external systems (LDAP, SAML, etc.)</li>
                    </ul>
                    <p>The report will still show role and permission analysis.</p>
                </div>
            </div>
            '''
        else:
            users_html = '''
            <div class="no-users">
                <div class="info-box">
                    <h3>👥 No Local Users Found</h3>
                    <p>No native realm users were found in this cluster. Users might be managed through external systems.</p>
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

                group_spans_content = group_spans if group_spans else '<span class="saml-group">No groups configured</span>'
                role_spans_content = role_spans if role_spans else '<span class="role-badge">No roles assigned</span>'

                mapping_cards += f'''
                <div class="mapping-card">
                    <h3>{safe_mapping_name}</h3>
                    <p><strong>SAML Groups:</strong></p>
                    {group_spans_content}
                    <p><strong>→ Assigned Roles:</strong></p>
                    {role_spans_content}
                </div>
                '''
        
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
        
        # Create space selection pills
        space_pills_html = ""
        if all_spaces:
            for space_name in all_spaces:
                display_name = space_name.replace('space:', '') if space_name != 'Default' else space_name
                safe_space_name = str(display_name).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
                space_pills_html += f'<div class="space-pill" onclick="filterBySpace(\'{space_name}\')" data-space="{space_name}">{safe_space_name}</div>'
        
        # Feature headers for matrix
        feature_headers = ''.join([f'<th>{str(feature).title()}</th>' for feature in features])
        
        # Safely get cluster name
        cluster_name = str(cluster_info.get('cluster_name', 'Unknown')).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')
        
        # Generate JSON data for JavaScript
        role_data_json = json.dumps([role_name for role_name in roles.keys()])
        space_data_json = json.dumps(all_spaces)
        role_space_data_json = json.dumps({role_name: role_data.get('space_permissions', {}) for role_name, role_data in roles.items()})
        user_role_mapping_json = json.dumps(users_analysis.get('role_user_mapping', {})) if users_analysis['available'] else json.dumps({})
        user_details_json = json.dumps(users_analysis.get('user_details', {})) if users_analysis['available'] else json.dumps({})
        
        # Generate conditional content
        space_filter_html = f'<div class="space-filter"><div class="filter-header"><h3>🏠 Filter by Space</h3></div><div class="space-pills" id="space-pills">{space_pills_html}</div></div>' if all_spaces else ''
        user_role_matrix_section = f'<h3>📊 User-Role Assignment Matrix</h3>{user_role_matrix_html}' if user_role_matrix_html else ''
        detailed_perms_content = detailed_perms_html if detailed_perms_html else '<p>No detailed permission data available.</p>'
        mapping_cards_content = mapping_cards if mapping_cards else '<p>No SAML mappings configured</p>'
        space_matrix_content = space_matrix_html if space_matrix_html else '<p>No space-specific permissions found. Roles may only have global permissions.</p>'
        es_privileges_content = es_privileges_html if es_privileges_html else '<p>No Elasticsearch cluster privileges found in roles.</p>'

        # Use template substitution instead of f-strings to avoid escaping issues
        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Elastic Role Permission Report with Users and Spaces</title>
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
        
        /* Space Filter Styles (NEW) */
        .space-filter {{ background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .space-pills {{ display: flex; flex-wrap: wrap; gap: 8px; }}
        .space-pill {{ background: #e8f5e8; border: 2px solid #c3e6c3; padding: 8px 15px; border-radius: 20px; cursor: pointer; transition: all 0.3s ease; font-size: 0.9em; }}
        .space-pill:hover {{ background: #d4f4d4; border-color: #a8d8a8; }}
        .space-pill.active {{ background: #28a745; color: white; border-color: #28a745; }}
        .space-pill.filtered-out {{ opacity: 0.3; }}
        
        /* Tab Styles */
        .tab-container {{ background: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 30px; }}
        .tab-nav {{ display: flex; border-bottom: 1px solid #ecf0f1; border-radius: 10px 10px 0 0; overflow: hidden; }}
        .tab-btn {{ background: #f8f9fa; border: none; padding: 15px 25px; cursor: pointer; font-size: 1em; font-weight: 500; color: #6c757d; transition: all 0.3s ease; flex: 1; }}
        .tab-btn:hover {{ background: #e9ecef; color: #495057; }}
        .tab-btn.active {{ background: #3498db; color: white; }}
        .tab-content {{ display: none; padding: 25px; }}
        .tab-content.active {{ display: block; }}
        
        /* User Styles */
        .user-stats {{ margin: 20px 0; }}
        .user-stat-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
        .user-stat-card {{ background: white; border-radius: 10px; padding: 20px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); transition: all 0.3s ease; }}
        .user-stat-card.clickable {{ cursor: pointer; }}
        .user-stat-card.clickable:hover {{ transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.15); }}
        .user-stat-card.active {{ background: linear-gradient(135deg, #2ecc71 0%, #27ae60 100%); color: white; }}
        .user-stat-card.inactive {{ background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); color: white; }}
        .user-stat-card.no-roles {{ background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); color: white; }}
        .user-stat-card.multiple-roles {{ background: linear-gradient(135deg, #9b59b6 0%, #8e44ad 100%); color: white; }}
        .user-stat-card.selected {{ border: 3px solid #fff; box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.5); }}
        .user-stat-card .stat-number {{ font-size: 2em; font-weight: bold; margin-bottom: 5px; }}
        .user-stat-card .stat-label {{ font-size: 0.9em; opacity: 0.9; }}
        
        .user-card {{ background: white; border-radius: 8px; padding: 20px; margin: 15px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); transition: all 0.3s ease; }}
        .user-card.disabled {{ opacity: 0.7; border-left: 4px solid #e74c3c; }}
        .user-card.enabled {{ border-left: 4px solid #27ae60; }}
        .user-card.filtered-out {{ display: none; }}
        .user-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 15px; }}
        .user-info h4 {{ margin: 0 0 5px 0; color: #2c3e50; font-size: 1.2em; }}
        .user-full-name {{ color: #7f8c8d; font-size: 0.9em; margin-bottom: 3px; }}
        .user-email {{ color: #3498db; font-size: 0.85em; }}
        .user-status {{ text-align: right; }}
        .status-badge {{ padding: 4px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; margin-bottom: 5px; display: block; }}
        .status-badge.enabled {{ background: #d4edda; color: #155724; }}
        .status-badge.disabled {{ background: #f8d7da; color: #721c24; }}
        .role-count {{ background: #17a2b8; color: white; padding: 3px 8px; border-radius: 10px; font-size: 0.75em; }}
        .user-roles {{ margin-top: 10px; }}
        .role-badges {{ margin-top: 8px; }}
        .role-badge {{ background: #28a745; color: white; padding: 4px 8px; border-radius: 12px; font-size: 0.8em; margin: 2px; display: inline-block; }}
        .role-badge.external {{ background: #6c757d; }}
        .role-badge.no-roles {{ background: #ffc107; color: #212529; }}
        .role-badge.known {{ background: #007bff; }}
        
        .user-role-matrix {{ overflow-x: auto; margin: 20px 0; }}
        .user-role-matrix .matrix-table {{ width: 100%; border-collapse: collapse; font-size: 0.85em; }}
        .user-role-matrix .matrix-table th {{ background-color: #34495e; color: white; padding: 8px 4px; text-align: center; font-weight: 600; }}
        .user-role-matrix .matrix-table th.user-header {{ background-color: #2c3e50; text-align: left; min-width: 120px; }}
        .user-role-matrix .matrix-table th.role-header-small {{ writing-mode: vertical-rl; text-orientation: mixed; max-width: 30px; }}
        .user-role-matrix .matrix-table td {{ padding: 6px 4px; text-align: center; border: 1px solid #ecf0f1; }}
        .user-role-matrix .matrix-table tr.enabled-user {{ background-color: #f8f9fa; }}
        .user-role-matrix .matrix-table tr.disabled-user {{ background-color: #f1f1f1; opacity: 0.7; }}
        .user-role-matrix .matrix-table tr.filtered-out {{ display: none; }}
        .user-role-matrix .has-role {{ background-color: #d4edda; color: #155724; font-weight: bold; }}
        .user-role-matrix .no-role {{ background-color: #f6f6f6; color: #6c757d; }}
        
        .no-users-available, .no-users {{ padding: 40px; text-align: center; }}
        .info-box {{ background: #e3f2fd; border: 1px solid #bbdefb; border-radius: 8px; padding: 30px; max-width: 600px; margin: 0 auto; }}
        .info-box h3 {{ margin-top: 0; color: #1976d2; }}
        .info-box ul {{ text-align: left; max-width: 400px; margin: 20px auto; }}
        .info-box p {{ color: #424242; line-height: 1.6; }}
        
        /* Space Matrix Styles */
        .space-matrix {{ margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 8px; border-left: 4px solid #28a745; }}
        .space-matrix h4 {{ margin-top: 0; color: #2c3e50; }}
        
        /* Detailed Permissions Styles */
        .detailed-role-card {{ background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; margin: 15px 0; transition: all 0.3s ease; }}
        .detailed-role-card.filtered-out {{ display: none; }}
        .role-header {{ background: #fff; padding: 20px; border-radius: 8px 8px 0 0; border-bottom: 1px solid #dee2e6; display: flex; justify-content: space-between; align-items: center; }}
        .role-header h4 {{ margin: 0; color: #2c3e50; font-size: 1.2em; }}
        .privilege-summary {{ display: flex; align-items: center; gap: 15px; }}
        .priv-count {{ background: #17a2b8; color: white; padding: 4px 8px; border-radius: 12px; font-size: 0.8em; }}
        .expand-details {{ background: #6c757d; color: white; border: none; padding: 8px 15px; border-radius: 5px; cursor: pointer; font-size: 0.9em; }}
        .expand-details:hover {{ background: #495057; }}
        .role-details {{ padding: 20px; }}
        .global-section, .features-section, .other-section, .raw-section, .space-info {{ margin: 15px 0; }}
        .space-info {{ background: #e3f2fd; padding: 10px; border-radius: 5px; border-left: 3px solid #2196f3; }}
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
            <p>Cluster: {cluster_name} | Generated: {timestamp} | ✨ With Detailed Sub-Feature Analysis, Local Users & Space Selection</p>
        </div>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-number" id="filtered-roles">{total_roles}</div>
                <div class="stat-label">Roles Shown</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{total_mappings}</div>
                <div class="stat-label">SAML Mappings</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="filtered-users">{total_users}</div>
                <div class="stat-label">Local Users</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{total_spaces}</div>
                <div class="stat-label">Kibana Spaces</div>
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

        {space_filter_html}

        <div class="tab-container">
            <div class="tab-nav">
                <button class="tab-btn active" onclick="switchTab('detailed-tab')">🔬 Detailed Permissions</button>
                <button class="tab-btn" onclick="switchTab('users-tab')">👥 Local Users</button>
                <button class="tab-btn" onclick="switchTab('kibana-tab')">🎛️ Kibana Overview</button>
                <button class="tab-btn" onclick="switchTab('spaces-tab')">🏠 Spaces</button>
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
                        {detailed_perms_content}
                    </div>
                </div>
            </div>
            
            <div id="users-tab" class="tab-content">
                <div id="filter-info-users" class="filter-info" style="display: none;">
                    Showing users with role: <strong id="filtered-role-name-users"></strong>
                </div>
                
                <div class="section-content">
                    <h2>👥 Local Users Analysis</h2>
                    {user_stats_html}
                    
                    <h3>📋 User Details</h3>
                    <div class="user-cards" id="user-cards">
                        {users_html}
                    </div>
                    
                    {user_role_matrix_section}
                </div>
            </div>
            
            <div id="kibana-tab" class="tab-content">
                <div id="filter-info-kibana" class="filter-info" style="display: none;">
                    Showing permissions for role: <strong id="filtered-role-name-kibana"></strong>
                </div>
                
                <div class="section-content">
                    <h2>📊 Role Permission Matrix (Global View)</h2>
                    <p style="color: #7f8c8d; margin-bottom: 20px;">
                        This matrix shows the highest permission level each role has across all spaces for each feature.
                    </p>
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
                        {mapping_cards_content}
                    </div>
                </div>

                <div class="section-content">
                    <h2>📊 Role Distribution Analysis</h2>
                    <div class="role-distribution">
                        {role_distribution}
                    </div>
                    <p style="color: #7f8c8d; font-style: italic; margin-top: 20px;">
                        This analysis categorizes your {total_roles} roles by their apparent function based on naming patterns.
                    </p>
                </div>
            </div>
            
            <div id="spaces-tab" class="tab-content">
                <div id="filter-info-spaces" class="filter-info" style="display: none;">
                    Showing space permissions for: <strong id="filtered-space-name"></strong>
                </div>
                
                <div class="section-content">
                    <h2>🏠 Space-Specific Permission Matrices</h2>
                    <p style="color: #7f8c8d; margin-bottom: 20px;">
                        Select a space above to see which roles have permissions in that specific space.
                    </p>
                    <div id="space-matrices">
                        {space_matrix_content}
                    </div>
                </div>
            </div>
            
            <div id="cluster-tab" class="tab-content">
                <div id="filter-info-cluster" class="filter-info" style="display: none;">
                    Showing cluster privileges for role: <strong id="filtered-role-name-cluster"></strong>
                </div>
                
                <div class="section-content">
                    <h2>⚙️ Elasticsearch Cluster Privileges</h2>
                    <div class="es-privileges" id="es-privileges">
                        {es_privileges_content}
                    </div>
                    <p style="color: #7f8c8d; font-style: italic;">
                        Shows the Elasticsearch cluster and index-level permissions granted by each role.
                    </p>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Role, user, and space data for filtering
        const roleData = {role_data_json};
        const spaceData = {space_data_json};
        const roleSpaceData = {role_space_data_json};
        const userRoleMapping = {user_role_mapping_json};
        const userDetails = {user_details_json};
        let selectedRole = null;
        let selectedSpace = null;
        
        // Initialize role and space pills
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
            selectedSpace = null; // Clear space filter when role is selected
            
            // Update pill states
            document.querySelectorAll('.role-pill').forEach(pill => {{
                if (pill.getAttribute('data-role') === roleName) {{
                    pill.classList.add('active');
                }} else {{
                    pill.classList.remove('active');
                }}
            }});
            
            // Clear space pill states
            document.querySelectorAll('.space-pill').forEach(pill => {{
                pill.classList.remove('active');
            }});
            
            // Apply role filtering to all relevant elements
            applyRoleFilter(roleName);
            
            // Show filter info
            updateFilterInfo('role', roleName);
            
            // Show clear button
            document.getElementById('clear-btn').style.display = 'inline-block';
            
            // Update filtered counts
            document.getElementById('filtered-roles').textContent = '1';
            
            // Count filtered users
            const filteredUserCount = userRoleMapping[roleName] ? userRoleMapping[roleName].length : 0;
            document.getElementById('filtered-users').textContent = filteredUserCount.toString();
        }}
        
        // Filter by space (NEW)
        function filterBySpace(spaceName) {{
            selectedSpace = spaceName;
            selectedRole = null; // Clear role filter when space is selected
            
            // Update space pill states
            document.querySelectorAll('.space-pill').forEach(pill => {{
                if (pill.getAttribute('data-space') === spaceName) {{
                    pill.classList.add('active');
                }} else {{
                    pill.classList.remove('active');
                }}
            }});
            
            // Clear role pill states
            document.querySelectorAll('.role-pill').forEach(pill => {{
                pill.classList.remove('active');
            }});
            
            // Apply space filtering
            applySpaceFilter(spaceName);
            
            // Show specific space matrix
            showSpaceMatrix(spaceName);
            
            // Show filter info
            updateFilterInfo('space', spaceName);
            
            // Show clear button
            document.getElementById('clear-btn').style.display = 'inline-block';
            
            // Update filtered counts
            const rolesInSpace = countRolesInSpace(spaceName);
            document.getElementById('filtered-roles').textContent = rolesInSpace.toString();
        }}
        
        // Apply role filtering to all elements
        function applyRoleFilter(roleName) {{
            // Filter matrix table rows
            document.querySelectorAll('#matrix-tbody tr').forEach(row => {{
                const roleCell = row.querySelector('td strong');
                if (roleCell && roleCell.textContent === roleName) {{
                    row.classList.remove('filtered-out');
                }} else {{
                    row.classList.add('filtered-out');
                }}
            }});
            
            // Filter user matrix rows
            document.querySelectorAll('#user-matrix-tbody tr').forEach(row => {{
                row.classList.add('filtered-out'); // Hide all first
            }});
            
            // Show users that have this role
            if (userRoleMapping[roleName]) {{
                const usersWithRole = userRoleMapping[roleName];
                document.querySelectorAll('#user-matrix-tbody tr').forEach(row => {{
                    const userCell = row.querySelector('td strong');
                    if (userCell && usersWithRole.includes(userCell.textContent)) {{
                        row.classList.remove('filtered-out');
                    }}
                }});
            }}
            
            // Filter user cards
            document.querySelectorAll('.user-card').forEach(card => {{
                const username = card.querySelector('.user-info h4').textContent;
                const user = userDetails[username];
                if (user && user.roles.includes(roleName)) {{
                    card.classList.remove('filtered-out');
                }} else {{
                    card.classList.add('filtered-out');
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
        }}
        
        // Apply space filtering (NEW)
        function applySpaceFilter(spaceName) {{
            // Filter roles that have permissions in this space
            const rolesInSpace = [];
            for (const [roleName, spaces] of Object.entries(roleSpaceData)) {{
                if (spaces[spaceName]) {{
                    // Check if role has any non-NONE permissions in this space
                    const hasPermissions = Object.values(spaces[spaceName]).some(perm => perm !== 'NONE');
                    if (hasPermissions) {{
                        rolesInSpace.push(roleName);
                    }}
                }}
            }}
            
            // Filter matrix table rows
            document.querySelectorAll('#matrix-tbody tr').forEach(row => {{
                const roleCell = row.querySelector('td strong');
                if (roleCell && rolesInSpace.includes(roleCell.textContent)) {{
                    row.classList.remove('filtered-out');
                }} else {{
                    row.classList.add('filtered-out');
                }}
            }});
            
            // Filter other elements similarly
            document.querySelectorAll('.detailed-role-card').forEach(card => {{
                const cardTitle = card.querySelector('.role-header h4');
                if (cardTitle && rolesInSpace.includes(cardTitle.textContent)) {{
                    card.classList.remove('filtered-out');
                }} else {{
                    card.classList.add('filtered-out');
                }}
            }});
            
            document.querySelectorAll('.es-role-card').forEach(card => {{
                const cardTitle = card.querySelector('h4');
                if (cardTitle && rolesInSpace.includes(cardTitle.textContent)) {{
                    card.classList.remove('filtered-out');
                }} else {{
                    card.classList.add('filtered-out');
                }}
            }});
        }}
        
        // Show specific space matrix (NEW)
        function showSpaceMatrix(spaceName) {{
            // Hide all space matrices
            document.querySelectorAll('.space-matrix').forEach(matrix => {{
                matrix.style.display = 'none';
            }});
            
            // Show the selected space matrix
            const targetMatrix = document.getElementById(`space-matrix-${{spaceName}}`);
            if (targetMatrix) {{
                targetMatrix.style.display = 'block';
            }}
        }}
        
        // Count roles in space (NEW)
        function countRolesInSpace(spaceName) {{
            let count = 0;
            for (const [roleName, spaces] of Object.entries(roleSpaceData)) {{
                if (spaces[spaceName]) {{
                    const hasPermissions = Object.values(spaces[spaceName]).some(perm => perm !== 'NONE');
                    if (hasPermissions) {{
                        count++;
                    }}
                }}
            }}
            return count;
        }}
        
        // Update filter info display
        function updateFilterInfo(filterType, filterValue) {{
            if (filterType === 'role') {{
                document.getElementById('filter-info-kibana').style.display = 'block';
                document.getElementById('filter-info-cluster').style.display = 'block';
                document.getElementById('filter-info-detailed').style.display = 'block';
                document.getElementById('filter-info-users').style.display = 'block';
                document.getElementById('filtered-role-name-kibana').textContent = filterValue;
                document.getElementById('filtered-role-name-cluster').textContent = filterValue;
                document.getElementById('filtered-role-name-detailed').textContent = filterValue;
                document.getElementById('filtered-role-name-users').textContent = filterValue;
                
                // Hide space filter info
                const spaceInfo = document.getElementById('filter-info-spaces');
                if (spaceInfo) spaceInfo.style.display = 'none';
            }} else if (filterType === 'space') {{
                const spaceInfo = document.getElementById('filter-info-spaces');
                if (spaceInfo) {{
                    spaceInfo.style.display = 'block';
                    document.getElementById('filtered-space-name').textContent = filterValue;
                }}
                
                // Hide role filter info
                document.getElementById('filter-info-kibana').style.display = 'none';
                document.getElementById('filter-info-cluster').style.display = 'none';
                document.getElementById('filter-info-detailed').style.display = 'none';
                document.getElementById('filter-info-users').style.display = 'none';
            }}
        }}
        
        // Clear filter
        function clearFilter() {{
            selectedRole = null;
            selectedSpace = null;
            
            // Reset pill states
            document.querySelectorAll('.role-pill, .space-pill').forEach(pill => {{
                pill.classList.remove('active');
            }});
            
            // Show all rows and cards
            document.querySelectorAll('.filtered-out').forEach(element => {{
                element.classList.remove('filtered-out');
                element.style.display = ''; // Reset display property
            }});
            
            // Hide all space matrices
            document.querySelectorAll('.space-matrix').forEach(matrix => {{
                matrix.style.display = 'none';
            }});
            
            // Hide filter info
            document.getElementById('filter-info-kibana').style.display = 'none';
            document.getElementById('filter-info-cluster').style.display = 'none';
            document.getElementById('filter-info-detailed').style.display = 'none';
            document.getElementById('filter-info-users').style.display = 'none';
            const spaceInfo = document.getElementById('filter-info-spaces');
            if (spaceInfo) spaceInfo.style.display = 'none';
            
            // Hide clear button
            document.getElementById('clear-btn').style.display = 'none';
            
            // Reset search box
            document.querySelector('.search-box').value = '';
            
            // Reset filtered counts
            document.getElementById('filtered-roles').textContent = roleData.length.toString();
            document.getElementById('filtered-users').textContent = Object.keys(userDetails).length.toString();
            
            // Show all role pills
            document.querySelectorAll('.role-pill').forEach(pill => {{
                pill.style.display = 'block';
            }});
            
            // Also clear user category filter
            clearUserFilter();
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
        
        // User filtering variables
        let selectedUserCategory = null;
        
        // Filter users by category
        function filterUsersByCategory(category) {{
            selectedUserCategory = category;
            
            // Update stat card states
            document.querySelectorAll('.user-stat-card').forEach(card => {{
                if (card.getAttribute('data-category') === category) {{
                    card.classList.add('selected');
                }} else {{
                    card.classList.remove('selected');
                }}
            }});
            
            // Filter user cards
            document.querySelectorAll('.user-card').forEach(card => {{
                const username = card.querySelector('.user-info h4').textContent;
                const user = userDetails[username];
                let shouldShow = false;
                
                if (user) {{
                    switch(category) {{
                        case 'active':
                            shouldShow = user.enabled === true;
                            break;
                        case 'inactive':
                            shouldShow = user.enabled === false;
                            break;
                        case 'no-roles':
                            shouldShow = user.role_count === 0;
                            break;
                        case 'multiple-roles':
                            shouldShow = user.role_count > 1;
                            break;
                    }}
                }}
                
                if (shouldShow) {{
                    card.classList.remove('filtered-out');
                }} else {{
                    card.classList.add('filtered-out');
                }}
            }});
            
            // Filter user matrix rows
            document.querySelectorAll('#user-matrix-tbody tr').forEach(row => {{
                const userCell = row.querySelector('td strong');
                if (userCell) {{
                    const username = userCell.textContent;
                    const user = userDetails[username];
                    let shouldShow = false;
                    
                    if (user) {{
                        switch(category) {{
                            case 'active':
                                shouldShow = user.enabled === true;
                                break;
                            case 'inactive':
                                shouldShow = user.enabled === false;
                                break;
                            case 'no-roles':
                                shouldShow = user.role_count === 0;
                                break;
                            case 'multiple-roles':
                                shouldShow = user.role_count > 1;
                                break;
                        }}
                    }}
                    
                    if (shouldShow) {{
                        row.classList.remove('filtered-out');
                    }} else {{
                        row.classList.add('filtered-out');
                    }}
                }}
            }});
            
            // Show filter info
            const filterInfo = document.getElementById('user-filter-info');
            const filterText = document.getElementById('user-filter-text');
            
            let categoryText = '';
            switch(category) {{
                case 'active':
                    categoryText = 'Active Users';
                    break;
                case 'inactive':
                    categoryText = 'Inactive Users';
                    break;
                case 'no-roles':
                    categoryText = 'Users Without Roles';
                    break;
                case 'multiple-roles':
                    categoryText = 'Users with Multiple Roles';
                    break;
            }}
            
            filterText.textContent = categoryText;
            filterInfo.style.display = 'block';
        }}
        
        // Clear user filter
        function clearUserFilter() {{
            selectedUserCategory = null;
            
            // Reset stat card states
            document.querySelectorAll('.user-stat-card').forEach(card => {{
                card.classList.remove('selected');
            }});
            
            // Show all user cards and matrix rows
            document.querySelectorAll('.user-card.filtered-out').forEach(card => {{
                card.classList.remove('filtered-out');
            }});
            
            document.querySelectorAll('#user-matrix-tbody tr.filtered-out').forEach(row => {{
                row.classList.remove('filtered-out');
            }});
            
            // Hide filter info
            document.getElementById('user-filter-info').style.display = 'none';
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

        # Now format the template with all the variables
        html_content = html_template.format(
            cluster_name=cluster_name,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_roles=stats['total_roles'],
            total_mappings=stats['total_mappings'],
            total_users=stats['total_users'],
            total_spaces=stats.get('total_spaces', 0),
            space_filter_html=space_filter_html,
            feature_headers=feature_headers,
            matrix_rows=matrix_rows,
            detailed_perms_content=detailed_perms_content,
            user_stats_html=user_stats_html,
            users_html=users_html,
            user_role_matrix_section=user_role_matrix_section,
            mapping_cards_content=mapping_cards_content,
            role_distribution=role_distribution,
            space_matrix_content=space_matrix_content,
            es_privileges_content=es_privileges_content,
            role_data_json=role_data_json,
            space_data_json=space_data_json,
            role_space_data_json=role_space_data_json,
            user_role_mapping_json=user_role_mapping_json,
            user_details_json=user_details_json
        )
        
        return html_content
    
    def create_csv_export(self, file_path: str):
        """Create enhanced CSV export of role permissions, users, and spaces with detailed breakdown"""
        import csv
        
        roles = self.analysis['roles']
        features = self.analysis['kibana_features']
        users_analysis = self.analysis['users']
        all_spaces = self.analysis.get('all_spaces', [])
        
        with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Enhanced header row with detailed columns including spaces
            header = ['Role', 'Spaces', 'Global_Privileges', 'Raw_Privilege_Count'] + [f'{feature}_Level' for feature in features] + [f'{feature}_Raw_Privileges' for feature in features]
            writer.writerow(header)
            
            # Role data rows
            for role_name, role_data in roles.items():
                perms = role_data['kibana_permissions']
                detailed_perms = role_data.get('detailed_permissions', {})
                role_spaces = role_data.get('spaces', [])
                
                # Basic info
                row = [role_name]
                
                # Spaces
                row.append('; '.join(role_spaces) if role_spaces else 'Default')
                
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
            
            # Add empty rows to separate sections
            writer.writerow([])
            writer.writerow(['=== SPACE-SPECIFIC PERMISSIONS ==='])
            writer.writerow([])
            
            # Space-specific permissions section (NEW)
            if all_spaces:
                for space_name in all_spaces:
                    writer.writerow([f'=== SPACE: {space_name} ==='])
                    writer.writerow(['Role'] + [f'{feature}_Level' for feature in features])
                    
                    for role_name, role_data in roles.items():
                        space_perms = role_data.get('space_permissions', {}).get(space_name, {})
                        if space_perms:
                            # Check if role has any permissions in this space
                            has_permissions = any(perm != 'NONE' for perm in space_perms.values())
                            if has_permissions:
                                space_row = [role_name]
                                for feature in features:
                                    space_row.append(space_perms.get(feature, 'NONE'))
                                writer.writerow(space_row)
                    
                    writer.writerow([])  # Empty row after each space
            
            # Add empty rows to separate sections
            writer.writerow([])
            writer.writerow(['=== USER DATA ==='])
            writer.writerow([])
            
            # User data section
            if users_analysis['available'] and users_analysis['total_users'] > 0:
                # User summary header
                writer.writerow(['User Summary'])
                writer.writerow(['Total Users', users_analysis['total_users']])
                writer.writerow(['Active Users', users_analysis['active_users']])
                writer.writerow(['Inactive Users', users_analysis['inactive_users']])
                writer.writerow(['Users Without Roles', len(users_analysis['users_without_roles'])])
                writer.writerow([])
                
                # User details header
                user_header = ['Username', 'Full_Name', 'Email', 'Enabled', 'Role_Count', 'Assigned_Roles']
                writer.writerow(user_header)
                
                # User details rows
                user_details = users_analysis['user_details']
                for username, user_data in user_details.items():
                    user_row = [
                        username,
                        user_data.get('full_name', ''),
                        user_data.get('email', ''),
                        'Yes' if user_data['enabled'] else 'No',
                        user_data['role_count'],
                        '; '.join(user_data['roles']) if user_data['roles'] else 'None'
                    ]
                    writer.writerow(user_row)
                
                # Add empty rows
                writer.writerow([])
                writer.writerow(['=== USER-ROLE MAPPING ==='])
                writer.writerow([])
                
                # Role-user mapping
                role_user_mapping = users_analysis['role_user_mapping']
                writer.writerow(['Role', 'Assigned_Users', 'User_Count'])
                for role_name, users_list in role_user_mapping.items():
                    if users_list:  # Only show roles with users
                        writer.writerow([
                            role_name,
                            '; '.join(users_list),
                            len(users_list)
                        ])
            else:
                writer.writerow(['User data not available or no users found'])
            
            # Add spaces summary
            writer.writerow([])
            writer.writerow(['=== SPACES SUMMARY ==='])
            writer.writerow([])
            writer.writerow(['Total Spaces Found', len(all_spaces)])
            writer.writerow(['Space Names', '; '.join(all_spaces) if all_spaces else 'Default only'])

def main():
    root = tk.Tk()
    app = KibanaMapperGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
