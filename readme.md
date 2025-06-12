# Elastic Role Permission Mapper (v4 Gold)

A comprehensive GUI tool for analyzing and visualizing **Elastic Cloud and Local Elasticsearch/Kibana permissions**, including **local user analysis** and **detailed sub-feature permission breakdown**.

## 🎯 Overview

The Elastic Role Permission Mapper (v4 Gold) helps security administrators, DevOps teams, and compliance officers understand and audit their Elasticsearch/Kibana access controls by providing:

- **🔌 Flexible Connectivity**: Connect to **Elastic Cloud** or **Local Elasticsearch instances** (v8.x optimized).
- **👥 Local User Analysis**: Fetch, analyze, and visualize **native realm users** and their role assignments.
- **🔬 Detailed Permission Analysis**: Granular breakdown of Kibana sub-feature permissions and raw privileges.
- **Interactive Role Filtering**: Focus on specific roles across all views.
- **Comprehensive Tabbed Interface**: Dedicated views for Detailed Permissions, Local Users, Kibana Overview, and Cluster Privileges.
- **Permission Matrix**: Visual grid showing role access to Kibana features.
- **SAML Mapping Analysis**: See which SAML groups get which roles.
- **Cluster Privilege Breakdown**: Detailed view of Elasticsearch permissions.
- **Advanced Export Capabilities**: Generate enhanced HTML reports and detailed CSV exports (now including user data).

## 🚀 Features

### 🔌 **NEW: Flexible Connectivity & Local Instance Support**
- **Connection Types**: GUI options to connect to **Elastic Cloud** or **Local Elasticsearch instances**.
- **Local Authentication**: Supports API Key, Basic Auth, or no authentication for local connections.
- **Multiple Hosts**: Specify comma-separated hosts for local clusters.

### 👥 **NEW: Local User Analysis**
- **User Fetching**: Retrieves native realm users from your Elasticsearch cluster.
- **User Statistics**: Provides counts of total, active, and inactive users.
- **User Details**: Displays username, full name, email, enabled status, and assigned roles for each user.
- **Role-User Mapping**: Shows which users are assigned to each role.
- **User-Role Matrix**: A new visual matrix in the HTML report showing user-to-role assignments.
- **CSV Export**: User data is now included in the CSV export.

### 🔬 **Detailed Permission Analysis**
- **Sub-Feature Breakdown**: Captures granular Kibana permissions (e.g., "Create Short URLs", "Store Search Sessions").
- **Minimal Permissions**: Identifies roles with custom sub-feature configurations.
- **Raw Privilege Display**: Shows exact privilege strings from Elasticsearch API.
- **Feature-Specific Analysis**: Drill down into individual features to see all granted permissions.
- **Global vs Feature Permissions**: Distinguishes between global privileges and feature-specific grants.

### 📊 **Comprehensive Role Analysis**
- **Permission Matrix**: Visual grid showing role access levels (Admin/Write/Read/Custom/None) for all Kibana features.
- **Custom Permission Level**: Identifies roles with granular sub-feature permissions.
- **Role Distribution**: Categorizes roles by function (Admin, Analyst, Viewer, Custom).
- **Interactive Filtering**: Click any role to filter all views to show only that role's permissions.
- **Space-Specific Permissions**: Shows how permissions apply to different Kibana spaces.

### 🔗 **SAML Integration**
- **Mapping Visualization**: Shows which SAML groups are assigned to which roles.
- **Group Analysis**: Identifies SAML attribute mappings and role assignments.
- **Role Assignment Tracking**: See complete SAML group → role → permission chain.

### ⚙️ **Elasticsearch Privileges**
- **Cluster Permissions**: Shows cluster-level privileges (monitor, manage, all, etc.).
- **Index Patterns**: Displays index-level permissions with expandable details.
- **Smart Collapsing**: Roles with many privileges show summary with expand/collapse functionality.
- **Privilege Categorization**: Organizes permissions by cluster vs index level.

### 📋 **Advanced Export Options**
- **Enhanced HTML Reports**: Beautiful, interactive reports with detailed permission breakdown and **new local users section**.
- **Detailed CSV Export**: Now includes raw privileges, global permissions, feature-specific data, and **local user information**.
- **Browser View**: Quick preview with all enhanced features.
- **Filtering Across Tabs**: Role filtering works across all views including detailed analysis and user views.

## 🛠️ Installation

### Prerequisites
- Python 3.x (developed with Python 3)
- Elasticsearch client library (v8.x is targeted by the script)

### Setup
1. **Clone or download** the `elastic_role_mapper.py` file.

2. **Install dependencies**:
   ```bash
   pip install 'elasticsearch>=8.0,<9.0'
   ```
   The script is optimized for Elasticsearch 8.x. If you encounter import errors, ensure this library is installed.

3. **Run the application**:
   ```bash
   python3 elastic_role_mapper.py
   ```
   (Use `python elastic_role_mapper.py` if `python` is aliased to Python 3 on your system)

## 🔧 Usage

### Connection Setup
1.  **Launch the application** - A GUI window will open.
2.  **Select Connection Type**:
    *   **Elastic Cloud**:
        *   Enter your **Cloud ID**.
        *   Enter your **API Key** (either `id:secret` format or base64 encoded).
    *   **Local Instance**:
        *   Enter **Host(s)** (comma-separated, e.g., `http://localhost:9200`).
        *   Select **Authentication Type**:
            *   `None`: No authentication.
            *   `API Key`: Enter your API Key (either `id:secret` format or base64 encoded).
            *   `Basic Auth`: Enter **Username** and **Password**.
3.  **Click "Connect"** - Status will show "Connected successfully".

### Data Analysis
1.  **Fetch Role & User Data** - Click to retrieve roles, SAML mappings, **local users**, and perform detailed permission analysis.
2.  **Choose your view**:
    *   **"Open in Browser"** - Quick interactive preview with all features, including user data.
    *   **"Generate HTML Report"** - Save a detailed report to a file, including user analysis.
    *   **"Export to CSV"** - Export permission matrix and user data to a CSV file.

### Interactive Features

#### 🔍 **Enhanced Role Filtering**
- **Role Pills**: Click any role name to filter all views to that role
- **Search Box**: Type to find specific roles quickly
- **Clear Filter**: Reset to show all roles
- **Cross-Tab Filtering**: Filtering works across all three tabs

#### 📑 **Comprehensive Tabbed Interface**
- **🔬 Detailed Permissions**: Granular analysis of sub-features and raw privileges.
- **👥 Local Users**: **NEW** - View user statistics, detailed user cards, and a user-role assignment matrix.
- **🎛️ Kibana Overview**: Role matrix, SAML mappings, distribution analysis, space permissions.
- **⚙️ Cluster Privileges**: Elasticsearch cluster and index permissions.

#### 🎛️ **NEW: Expandable Detailed Content**
- **Role Details**: Click "Show Details" to expand full permission breakdown
- **Sub-Feature Display**: See minimal permissions and custom configurations
- **Raw Privilege Access**: Toggle display of exact privilege strings
- **Feature-Specific Raw Data**: View privileges granted for each specific feature

## 📊 Report Sections

### 🔬 Detailed Permissions Tab
- **Role Cards**: Expandable cards showing complete permission breakdown.
- **Global Privileges**: Shows cluster-wide permissions like "all" or "read".
- **Feature Breakdown**: Detailed analysis of each Kibana feature's permissions.
- **Sub-Feature Display**: Shows minimal permissions, custom configurations.
- **Raw Privilege Access**: Complete privilege strings with toggle display.
- **Privilege Statistics**: Count of total privileges per role.

### 👥 NEW: Local Users Tab
- **User Statistics**: Cards displaying total, active, inactive users, and users without roles/multiple roles.
- **User Cards**: Individual cards for each local user showing:
    - Username, Full Name, Email
    - Enabled/Disabled status
    - Assigned roles (with badges indicating known vs. external roles)
- **User-Role Assignment Matrix**: A table visualizing which users are assigned to which defined roles.

### 🎛️ Kibana Overview Tab
- **Space-Specific Permissions**: Shows how permissions apply to different Kibana spaces (when a role is selected).
- **Role Permission Matrix**: Grid showing role access with "Custom" level for granular permissions.
- **SAML Role Mappings**: Cards showing SAML group → role assignments.
- **Role Distribution**: Bar chart categorizing roles by function.

### ⚙️ Cluster Privileges Tab
- **Elasticsearch Privileges**: Detailed cluster and index permissions for each role.
- **Expandable Details**: Smart handling of roles with many privileges.
- **Organized Display**: Clean cards showing both cluster and index permissions.

## 🔐 Security & Compliance

### Use Cases
- **Detailed Security Audits**: Understand granular sub-feature access permissions.
- **Local User Audits**: Review native realm user access and role assignments.
- **Compliance Reporting**: Generate comprehensive documentation with raw privilege and user data.
- **Access Reviews**: Detailed review of role assignments, sub-feature permissions, and user access.
- **Permission Troubleshooting**: Debug user access issues with detailed privilege analysis.
- **Role Optimization**: Identify redundant permissions at the sub-feature level.
- **Sub-Feature Analysis**: Understand which roles have access to specific Kibana sub-features.

### Best Practices
- **Regular User Audits**: Utilize the local user analysis for periodic reviews of native realm accounts.
- **Granular Reviews**: Use detailed analysis to review sub-feature permissions.
- **Raw Privilege Auditing**: Review actual privilege strings for compliance.
- **Custom Permission Analysis**: Monitor roles with "Custom" permission levels.
- **Space-Specific Auditing**: Review permissions across different Kibana spaces.
- **Sub-Feature Governance**: Establish policies for sub-feature access.

## 🎨 Enhanced Output Examples

### HTML Report Features
- **NEW: Local Users Tab**: Dedicated section for user statistics, user details, and user-role matrix.
- **Detailed Permission Cards** with expandable role analysis.
- **Sub-Feature Visualization** showing minimal and custom permissions.
- **Raw Privilege Display** with toggle functionality.
- **Interactive filtering** across all four tabs.
- **Tabbed navigation** (Detailed Permissions, Local Users, Kibana Overview, Cluster Privileges).
- **Enhanced color-coding** for permission levels.
- **Space-specific permission display**.
- **Responsive design**.

### CSV Export
- **NEW: User Data Section**: Includes user summary, user details (username, full name, email, enabled, roles), and role-to-user mappings.
- **Raw Privilege Data**: Complete privilege strings for each feature.
- **Global Privileges Column**: Shows cluster-wide permissions.
- **Privilege Count Statistics**: Number of privileges per role.
- **Feature-Specific Raw Data**: Detailed breakdown by Kibana feature.

## ⚠️ Compatibility

### Elasticsearch Versions
- **Targeted**: Elasticsearch 8.x clusters (using `elasticsearch` client library v8.x).
- **Compatibility**: Should generally work with modern Elasticsearch versions that support the security APIs used.
- **Connection**: Supports Elastic Cloud and Local Elasticsearch instances.

### Authentication
- **Elastic Cloud**: API Key (ID:Secret or Base64).
- **Local Instances**:
    - None
    - API Key (ID:Secret or Base64)
    - Basic Authentication (Username/Password)
- **SAML-based user management**: Role mappings are analyzed.
- **Native Realm Users**: Fetched and analyzed if present and accessible.

## 🐛 Troubleshooting

### Connection Issues
- **Authentication Failures**:
    - **Cloud**: Verify Cloud ID and API Key (format and validity).
    - **Local**: Double-check host URLs (including `http://` or `https://`), and selected authentication details (API Key, Username/Password).
- **Connection Errors**: Ensure Elasticsearch instance is reachable from where the script is run. Check firewalls or network configurations.
- **Media Type/API Errors**: The script targets Elasticsearch 8.x. Using it against significantly older or newer versions might lead to API incompatibilities. Ensure the `elasticsearch` Python client version matches the cluster's major version.

### Data Fetching & Analysis
- **No Local Users Displayed**:
    - The native realm might not be enabled or used in your cluster.
    - The connected user/API key might lack permissions to fetch users (`manage_security` or `read_security` typically needed).
- **No Detailed Permissions**: Normal for simple roles without granular Kibana sub-feature privileges.
- **Missing Sub-features**: Some roles may only have high-level Kibana permissions (e.g., global `all` or `read`).
- **Raw Privilege Access**: Requires appropriate API key permissions to read security settings.

### Performance
- **Analysis Time**: Fetching and analyzing data from large clusters might take some time. The operations are threaded to keep the GUI responsive.
- **Large Role/User Counts**: The GUI and reports are designed to handle a reasonable number of roles and users. Extremely large datasets might impact performance.

## 🆕 What's New in v4 Gold (this version)

This version (`elastic_role_mapper.py`) introduces major enhancements:

- **🔌 Local Elasticsearch Instance Support**:
    - GUI options to connect to local ES instances.
    - Support for API Key, Basic Auth, or no authentication for local connections.
- **👥 Comprehensive Local User Analysis**:
    - Fetching and display of native realm users.
    - User statistics (total, active, inactive).
    - Detailed user cards in HTML report (username, full name, email, status, roles).
    - New "Local Users" tab in the HTML report.
    - User-Role assignment matrix in the HTML report.
    - User data included in CSV export.
- **UI Enhancements**:
    - Connection panel updated for Cloud/Local selection and local auth options.
    - Actions and results organized for clarity.
- **Reporting Improvements**:
    - HTML report now includes a dedicated "Local Users" tab.
    - CSV export now contains detailed user information and role-to-user mappings.
- **Code Refinements**:
    - Connection logic updated to handle different connection types and authentication methods.
    - Data fetching and analysis expanded to include users.
    - HTML and CSV generation updated to incorporate user data.

## 📝 License

This tool is provided as-is for educational and administrative purposes. Use in accordance with your organization's security policies.

## 🤝 Contributing

This is a standalone tool. For feature requests or bug reports, please document your Elasticsearch version, client version, and specific error messages.

---

**Note**: This enhanced tool provides read-only analysis of existing permissions with detailed sub-feature breakdown. It does not modify roles, users, or security settings in your Elasticsearch cluster.
