# CSR Helpful Scripts

A collection of Python scripts to help you interact with the Contrast Security API and automate common tasks.

## 🚀 Getting Started

### Prerequisites

- Python 3.x (latest version recommended)
- Contrast Security account with API access
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Contrast-Security-OSS/CSR-Helpful-Scripts.git
   cd CSR-Helpful-Scripts
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up your credentials**
   
   Create a `.creds` file in the root directory using the provided template:
   ```bash
   cp template.creds .creds
   chmod 600 .creds
   ```

   `.creds` stores credentials in plaintext. `chmod 600` restricts read access to your user account only.

   Edit `.creds` and fill in your Contrast Security credentials:
   ```
   CONTRAST_URL=https://your-contrast-instance.com/Contrast
   ORG_ID=your-organization-id
   USERNAME=your-username
   API_KEY=your-api-key
   SERVICE_KEY=your-service-key
   APP_ID=your-app-id
   ```

   > ⚠️ **Important:** Never commit the `.creds` file to version control. It's already included in `.gitignore`.

## 📝 Usage

### Running a Script

1. Navigate to the script directory:
   ```bash
   cd script-folder-name
   ```

2. Run the script:
   ```bash
   python script-name.py
   ```

3. **Enter credentials:**
   - If you have a `.creds` file configured, simply press **Enter** when prompted to use the saved credentials
   - Otherwise, manually enter your credentials when prompted

## 📂 Available Scripts

| Script | Description |
|--------|-------------|
| `app-add-label` | Bulk add or remove tags from applications |
| `correlate-routes-to-vulns` | Determine if vulnerabilities still exist on routes |
| `distribute-parent-app-rbac-to-children` | Distribute parent application RBAC to child applications |
| `get-licensed-apps` | Get all licensed applications and their server information |
| `get-licensed-servers` | Get all licensed servers |
| `get-scan-data` | Retrieve scan data for SAST projects |
| `inventory-windows-webapps` | Inventory Windows web applications |
| `policy-add-to-all-orgs` | Add policies to all organizations |
| `reporting` | Generate various reports (languages, vulnerabilities, protect vs assess) |
| `scan-add-label` | Add labels to SAST scan projects |
| `toggle-server-protect` | Toggle server protect license |
| `vulnerabilities-by-business-unit` | Get vulnerabilities grouped by business unit |
| `vulns-and-prompts` | Get vulnerability and prompt details |

> 📖 Each script directory contains its own `README.md` with detailed usage instructions.

## 🐛 Bug Reports & Feature Requests

If you discover any bugs or have feature requests:

1. **Open an issue** in this repository with details about the bug or feature
2. **Contact your CSA** (Customer Success Architect) during your weekly/biweekly calls
3. **Submit a Pull Request** if you've fixed a bug or added a feature

## 🔒 Security

- **Never commit credentials** to version control
- Keep your `.creds` file secure and private (run `chmod 600 .creds` after creating it)
- Regularly rotate your API keys and service keys
- Keep your Python dependencies up to date:
  ```bash
  pip install --upgrade -r requirements.txt
  ```

## 🗂️ Handling Exported Data

These scripts produce CSV and JSON exports that often contain customer data, including application names, vulnerability details, server hostnames, user emails, and organization metadata.

**Default classification.** Treat all exports as confidential customer data unless explicitly cleared otherwise.

**Storage.**

- Store exports only on encrypted disks.
- Do not commit exports to source control. `.gitignore` covers the common output filenames but the broad `*.csv` rule can be overridden, double check `git status` before committing.
- Do not upload exports to consumer file-sharing tools, public pastebins, or unapproved AI tools. NDA obligations cover any third-party processing of customer data.

**Retention.**

- Delete exports once the analysis they were generated for is complete.
- Macro backup tools such as Time Machine can capture exports to long-term storage. Consider excluding the working directory from backup, or running scripts from a path your backup policy excludes.

**Sharing.**

- Share exports only with personnel who have a need-to-know on the engagement and who are covered by the relevant NDA.
- When sharing, prefer access-controlled platforms (e.g. a customer-specific shared folder) over email attachments.

## 📄 License

See the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

For support, please contact your Contrast Security Customer Success Architect.

---

**Note:** These scripts are provided as-is for use by Contrast Security customers and partners. Always test scripts in a non-production environment first.
