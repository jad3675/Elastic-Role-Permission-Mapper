# Enhanced Elastic Role Permission Mapper

A comprehensive GUI tool for analyzing and visualizing Elastic Cloud Kibana permissions and Elasticsearch cluster privileges with **detailed sub-feature permission analysis**.

## 🎯 Overview

The Enhanced Elastic Role Permission Mapper helps security administrators, DevOps teams, and compliance officers understand and audit their Elasticsearch/Kibana access controls by providing:

- **🔬 Detailed permission analysis** - Granular breakdown of sub-feature permissions and raw privileges
- **Interactive role filtering** - Focus on specific roles across all views
- **Enhanced tabbed interface** - Separate views for detailed analysis, Kibana overview, and Elasticsearch privileges
- **Permission matrix** - Visual grid showing role access to Kibana features
- **SAML mapping analysis** - See which SAML groups get which roles
- **Cluster privilege breakdown** - Detailed view of Elasticsearch permissions
- **Advanced export capabilities** - Generate enhanced HTML reports and detailed CSV exports

## 🚀 Features

### 🔬 **NEW: Detailed Permission Analysis**
- **Sub-Feature Breakdown**: Captures granular permissions like "Create Short URLs", "Store Search Sessions", etc.
- **Minimal Permissions**: Identifies roles with custom sub-feature configurations
- **Raw Privilege Display**: Shows exact privilege strings from Elasticsearch API
- **Feature-Specific Analysis**: Drill down into individual features to see all granted permissions
- **Global vs Feature Permissions**: Distinguishes between global privileges and feature-specific grants

### 📊 **Enhanced Role Analysis**
- **Permission Matrix**: Visual grid showing role access levels (Admin/Write/Read/Custom/None) for all Kibana features
- **NEW: Custom Permission Level**: Identifies roles with granular sub-feature permissions
- **Role Distribution**: Categorizes roles by function (Admin, Analyst, Viewer, Custom)
- **Interactive Filtering**: Click any role to filter all views to show only that role's permissions
- **Space-Specific Permissions**: Shows how permissions apply to different Kibana spaces

### 🔗 **SAML Integration**
- **Mapping Visualization**: Shows which SAML groups are assigned to which roles
- **Group Analysis**: Identifies SAML attribute mappings and role assignments
- **Role Assignment Tracking**: See complete SAML group → role → permission chain

### ⚙️ **Elasticsearch Privileges**
- **Cluster Permissions**: Shows cluster-level privileges (monitor, manage, all, etc.)
- **Index Patterns**: Displays index-level permissions with expandable details
- **Smart Collapsing**: Roles with many privileges show summary with expand/collapse functionality
- **Privilege Categorization**: Organizes permissions by cluster vs index level

### 📋 **Advanced Export Options**
- **Enhanced HTML Reports**: Beautiful, interactive reports with detailed permission breakdown
- **Detailed CSV Export**: Now includes raw privileges, global permissions, and feature-specific data
- **Browser View**: Quick preview with all enhanced features
- **Filtering Across Tabs**: Role filtering works across all views including detailed analysis

## 🛠️ Installation

### Prerequisites
- Python 3.7+
- Elasticsearch client library (8.x recommended)

### Setup
1. **Clone or download** the enhanced `kibana_role_mapper.py` file

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
   python kibana_role_mapper.py
   ```

## 🔧 Usage

### Connection Setup
1. **Launch the application** - A GUI window will open
2. **Enter your Elastic Cloud credentials**:
   - **Cloud ID**: Found in your Elastic Cloud console
   - **API Key**: Either `id:secret` format or base64 encoded
3. **Click Connect** - Status will show "Connected successfully"

### Enhanced Data Analysis
1. **Fetch Role Data** - Click to retrieve all roles with detailed permission analysis
2. **Choose your view**:
   - **"Open in Browser"** - Quick interactive preview with all enhanced features
   - **"Generate HTML Report"** - Save detailed report to file
   - **"Export to CSV"** - Export enhanced permission matrix with raw privilege data

### Interactive Features

#### 🔍 **Enhanced Role Filtering**
- **Role Pills**: Click any role name to filter all views to that role
- **Search Box**: Type to find specific roles quickly
- **Clear Filter**: Reset to show all roles
- **Cross-Tab Filtering**: Filtering works across all three tabs

#### 📑 **Enhanced Tabbed Interface**
- **🔬 Detailed Permissions**: NEW - Granular analysis of sub-features and raw privileges
- **🎛️ Kibana Overview**: Role matrix, SAML mappings, distribution analysis, space permissions
- **⚙️ Cluster Privileges**: Elasticsearch cluster and index permissions

#### 🎛️ **NEW: Expandable Detailed Content**
- **Role Details**: Click "Show Details" to expand full permission breakdown
- **Sub-Feature Display**: See minimal permissions and custom configurations
- **Raw Privilege Access**: Toggle display of exact privilege strings
- **Feature-Specific Raw Data**: View privileges granted for each specific feature

## 📊 Enhanced Report Sections

### 🔬 NEW: Detailed Permissions Tab
- **Role Cards**: Expandable cards showing complete permission breakdown
- **Global Privileges**: Shows cluster-wide permissions like "all" or "read"
- **Feature Breakdown**: Detailed analysis of each Kibana feature's permissions
- **Sub-Feature Display**: Shows minimal permissions, custom configurations
- **Raw Privilege Access**: Complete privilege strings with toggle display
- **Privilege Statistics**: Count of total privileges per role

### 🎛️ Enhanced Kibana Overview Tab
- **Space-Specific Permissions**: Shows how permissions apply to different Kibana spaces
- **Role Permission Matrix**: Grid showing role access with new "Custom" level
- **SAML Role Mappings**: Cards showing SAML group → role assignments
- **Role Distribution**: Bar chart categorizing roles by function

### ⚙️ Cluster Privileges Tab  
- **Elasticsearch Privileges**: Detailed cluster and index permissions for each role
- **Expandable Details**: Smart handling of roles with many privileges
- **Organized Display**: Clean cards showing both cluster and index permissions

## 🔐 Enhanced Security & Compliance

### Use Cases
- **Detailed Security Audits**: Understand granular sub-feature access permissions
- **Compliance Reporting**: Generate comprehensive documentation with raw privilege data
- **Access Reviews**: Detailed review of role assignments and sub-feature permissions
- **Permission Troubleshooting**: Debug user access issues with detailed privilege analysis
- **Role Optimization**: Identify redundant permissions at the sub-feature level
- **Sub-Feature Analysis**: Understand which roles have access to specific Kibana sub-features

### Best Practices
- **Granular Reviews**: Use detailed analysis to review sub-feature permissions
- **Raw Privilege Auditing**: Review actual privilege strings for compliance
- **Custom Permission Analysis**: Monitor roles with "Custom" permission levels
- **Space-Specific Auditing**: Review permissions across different Kibana spaces
- **Sub-Feature Governance**: Establish policies for sub-feature access

## 🎨 Enhanced Output Examples

### Enhanced HTML Report Features
- **NEW: Detailed Permission Cards** with expandable role analysis
- **Sub-Feature Visualization** showing minimal and custom permissions
- **Raw Privilege Display** with toggle functionality
- **Interactive filtering** across all three tabs
- **Tabbed navigation** between detailed analysis, Kibana overview, and ES permissions
- **Enhanced color-coding** (Red=Admin, Blue=Write, Green=Read, Yellow=Custom, Gray=None)
- **Space-specific permission display**
- **Responsive design** for desktop and tablet viewing

### Enhanced CSV Export
- **Raw Privilege Data**: Complete privilege strings for each feature
- **Global Privileges Column**: Shows cluster-wide permissions
- **Privilege Count Statistics**: Number of privileges per role
- **Feature-Specific Raw Data**: Detailed breakdown by Kibana feature
- **Enhanced analysis capabilities** for spreadsheet tools

## ⚠️ Compatibility

### Elasticsearch Versions
- **Recommended**: Elasticsearch 8.x clusters with elasticsearch client 8.x
- **Enhanced Analysis**: Works with all modern privilege structures
- **Supported**: Works with Elasticsearch 7.x, 8.x, and 9.x clusters
- **Elastic Cloud**: Optimized for Elastic Cloud deployments

### Authentication
- **API Key authentication** (recommended for security)
- **SAML-based user management** with detailed group analysis
- **Role-based access control** with sub-feature analysis

## 🐛 Troubleshooting

### Connection Issues
- **Media type errors**: Try downgrading elasticsearch client to match cluster version
- **Authentication failures**: Verify API key format and permissions
- **Network errors**: Check Cloud ID format and network connectivity

### Enhanced Data Analysis
- **No detailed permissions**: Normal for simple roles without sub-features
- **Missing sub-features**: Some roles may only have high-level permissions
- **Raw privilege access**: Requires appropriate API key permissions
- **Custom permission display**: Indicates roles with granular sub-feature access

### Performance
- **Enhanced analysis**: Tool efficiently handles detailed permission parsing
- **Large role counts**: Optimized filtering across all tabs
- **Detailed reports**: HTML generation optimized for comprehensive data display

## 🆕 What's New

### Version 2.0 Enhancements
- **🔬 Detailed Permission Analysis**: Complete sub-feature permission breakdown
- **📊 Enhanced Permission Levels**: New "Custom" level for granular permissions
- **🎯 Raw Privilege Access**: View exact privilege strings from Elasticsearch
- **🏠 Space-Specific Analysis**: Understand permissions across Kibana spaces
- **📈 Advanced CSV Export**: Enhanced data export with raw privilege information
- **🎨 Improved UI**: Three-tab interface with detailed analysis capabilities
- **🔍 Cross-Tab Filtering**: Role filtering works across all analysis views

## 📝 License

This tool is provided as-is for educational and administrative purposes. Use in accordance with your organization's security policies.

## 🤝 Contributing

This is a standalone tool. For feature requests or bug reports, please document your Elasticsearch version, client version, and specific error messages.

---

**Note**: This enhanced tool provides read-only analysis of existing permissions with detailed sub-feature breakdown. It does not modify roles, users, or security settings in your Elasticsearch cluster.
