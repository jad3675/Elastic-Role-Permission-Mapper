# Elastic Role Permission Mapper

A comprehensive GUI tool for analyzing and visualizing Elastic Cloud Kibana permissions and Elasticsearch cluster privileges.

## 🎯 Overview

The Elastic Role Permission Mapper helps security administrators, DevOps teams, and compliance officers understand and audit their Elasticsearch/Kibana access controls by providing:

- **Interactive role filtering** - Focus on specific roles across all views
- **Tabbed interface** - Separate views for Kibana permissions vs Elasticsearch privileges  
- **Permission matrix** - Visual grid showing role access to Kibana features
- **SAML mapping analysis** - See which SAML groups get which roles
- **Cluster privilege breakdown** - Detailed view of Elasticsearch permissions
- **Export capabilities** - Generate HTML reports and CSV exports

## 🚀 Features

### 📊 **Role Analysis**
- **Permission Matrix**: Visual grid showing role access levels (Admin/Write/Read/None) for all Kibana features
- **Role Distribution**: Categorizes roles by function (Admin, Analyst, Viewer, Custom)
- **Interactive Filtering**: Click any role to filter all views to show only that role's permissions

### 🔗 **SAML Integration**
- **Mapping Visualization**: Shows which SAML groups are assigned to which roles
- **Group Analysis**: Identifies SAML attribute mappings and role assignments

### ⚙️ **Elasticsearch Privileges**
- **Cluster Permissions**: Shows cluster-level privileges (monitor, manage, all, etc.)
- **Index Patterns**: Displays index-level permissions with expandable details
- **Smart Collapsing**: Roles with many privileges show summary with expand/collapse functionality

### 📋 **Export Options**
- **HTML Reports**: Beautiful, interactive reports with filtering and tabs
- **CSV Export**: Role permission matrix for spreadsheet analysis
- **Browser View**: Quick preview without saving files

## 🛠️ Installation

### Prerequisites
- Python 3.7+
- Elasticsearch client library (8.x recommended)

### Setup
1. **Clone or download** the `elastic_role_mapper.py` file

2. **Install dependencies**:
   ```bash
   pip install 'elasticsearch>=8.0,<9.0'
   ```
   
   > **Note**: For Elasticsearch 7.x clusters, use:
   > ```bash
   > pip install 'elasticsearch>=7.0,<8.0'
   > ```

3. **Run the application**:
   ```bash
   python elastic_role_mapper.py
   ```

## 🔧 Usage

### Connection Setup
1. **Launch the application** - A GUI window will open
2. **Enter your Elastic Cloud credentials**:
   - **Cloud ID**: Found in your Elastic Cloud console
   - **API Key**: Either `id:secret` format or base64 encoded
3. **Click Connect** - Status will show "Connected successfully"

### Data Analysis
1. **Fetch Role Data** - Click to retrieve all roles and mappings from your cluster
2. **Choose your view**:
   - **"Open in Browser"** - Quick interactive preview
   - **"Generate HTML Report"** - Save report to file
   - **"Export to CSV"** - Export permission matrix

### Interactive Features

#### 🔍 **Role Filtering**
- **Role Pills**: Click any role name to filter all views to that role
- **Search Box**: Type to find specific roles quickly
- **Clear Filter**: Reset to show all roles

#### 📑 **Tabbed Interface**
- **🎛️  Permissions**: Role matrix, SAML mappings, distribution analysis
- **⚙️ Cluster Privileges**: Elasticsearch cluster and index permissions

#### 🎛️ **Expandable Content**
- **Cluster Privileges**: Roles with many privileges show "+X more" - click to expand
- **Index Patterns**: Click summaries to see detailed index privilege patterns

## 📊 Report Sections

###  Permissions Tab
- **Role Permission Matrix**: Grid showing role access to Discover, Dashboard, Visualize, etc.
- **SAML Role Mappings**: Cards showing SAML group → role assignments
- **Role Distribution**: Bar chart categorizing roles by function

### Cluster Privileges Tab  
- **Elasticsearch Privileges**: Detailed cluster and index permissions for each role
- **Expandable Details**: Smart handling of roles with many privileges
- **Organized Display**: Clean cards showing both cluster and index permissions

## 🔐 Security & Compliance

### Use Cases
- **Security Audits**: Understand who has access to what
- **Compliance Reporting**: Generate documentation for auditors
- **Access Reviews**: Regular review of role assignments and privileges
- **Troubleshooting**: Debug user access issues by examining role permissions
- **Role Optimization**: Identify redundant or overprivileged roles

### Best Practices
- **Regular Reviews**: Generate reports monthly or quarterly
- **Principle of Least Privilege**: Use reports to identify overprivileged roles
- **Documentation**: Save HTML reports for compliance records
- **Change Tracking**: Compare reports over time to track permission changes

## 🎨 Output Examples

### HTML Report Features
- **Interactive filtering** by role
- **Tabbed navigation** between Kibana and ES permissions  
- **Color-coded permissions** (Red=Admin, Blue=Write, Green=Read, Gray=None)
- **Expandable privilege lists** for roles with many permissions
- **Responsive design** for desktop and tablet viewing

### CSV Export
- Simple matrix format: Role names vs Kibana features
- Easy import into Excel or other analysis tools
- Suitable for automated processing or further analysis

## ⚠️ Compatibility

### Elasticsearch Versions
- **Recommended**: Elasticsearch 8.x clusters with elasticsearch client 8.x
- **Supported**: Works with Elasticsearch 7.x, 8.x, and 9.x clusters
- **Elastic Cloud**: Optimized for Elastic Cloud deployments

### Authentication
- **API Key authentication** (recommended for security)
- **SAML-based user management** (no local users required)
- **Role-based access control** analysis

## 🐛 Troubleshooting

### Connection Issues
- **Media type errors**: Try downgrading elasticsearch client to match cluster version
- **Authentication failures**: Verify API key format and permissions
- **Network errors**: Check Cloud ID format and network connectivity

### Missing Data
- **No SAML mappings**: Normal if using built-in authentication
- **Empty role data**: Check if API key has sufficient privileges to read security settings
- **Missing privileges**: Some roles may not have Elasticsearch cluster privileges

### Performance
- **Large role counts**: Tool handles 50+ roles efficiently with filtering
- **Many privileges**: Smart collapsing keeps interface responsive
- **Report generation**: HTML reports work well with hundreds of roles

## 📝 License

This tool is provided as-is for educational and administrative purposes. Use in accordance with your organization's security policies.

## 🤝 Contributing

This is a standalone tool. For feature requests or bug reports, please document your Elasticsearch version, client version, and specific error messages.

---

**Note**: This tool provides read-only analysis of existing permissions. It does not modify roles, users, or security settings in your Elasticsearch cluster.
