# App Add Label

This script allows you to add or remove tags from Contrast Security applications in bulk.

## Prerequisites

- Python 3.x installed
- Required Python packages (install with `pip install -r ../requirements.txt`)
- Contrast Security account with API access

## Setup

1. **Create a `.creds` file** in the parent directory (`CSR-Helpful-Scripts/.creds`) with your Contrast credentials:

```
CONTRAST_URL=https://your-contrast-instance.com/Contrast
ORG_ID=your-organization-id
USERNAME=your-username
API_KEY=your-api-key
SERVICE_KEY=your-service-key
```

2. **Configure tags.json** - This file defines the default tags to add or remove:

```json
{
    "applications_id": [""],
    "tags": [],
    "tags_remove": ["Test"]
}
```

- `tags`: Array of tags to add to applications
- `tags_remove`: Array of tags to remove from applications

3. **Configure specific_apps.csv (Optional)** - Use this file to specify which applications should be tagged and with what tags:

**Format:**
```csv
application_id
application_id,tag1,tag2,tag3
```

**Examples:**
```csv
00000000-0000-0000-0000-000000000000
00000000-0000-0000-0000-000000000001,CustomTag1,CustomTag2
```

## How It Works

### Tagging Behavior

1. **If `specific_apps.csv` is empty or doesn't exist:**
   - The script will apply the tags from `tags.json` to **all applications** in your organization

2. **If `specific_apps.csv` contains app IDs only (no tags):**
   - The script will apply the tags from `tags.json` to **only those specific applications**

3. **If `specific_apps.csv` contains app IDs with specific tags:**
   - The script will **override** the tags from `tags.json` and use the specific tags for those applications
   - Format: `application_id,tag1,tag2,tag3`

### Tag Removal

- Tags specified in the `tags_remove` field in `tags.json` will be removed from the applications
- **Note:** At this time, there is no way to specify tags to be removed from specific applications via `specific_apps.csv`, but this may be added in the future

## Running the Script

1. **Open a terminal or command prompt**

2. **Navigate to the app-add-label directory:**
   ```bash
   cd app-add-label
   ```

3. **Run the script:**
   ```bash
   python app-add-label.py
   ```

4. **Enter credentials:**
   - If all your credentials are defined in the `.creds` file, simply **press Enter 5 times** to accept the default values
   - Otherwise, enter the requested information when prompted:
     - Contrast URL
     - Organization ID
     - Username
     - API Key
     - Service Key

5. **The script will:**
   - Load your credentials
   - Read the `tags.json` file
   - Read the `specific_apps.csv` file (if it exists)
   - Fetch applications from your Contrast organization
   - Apply or remove tags based on your configuration
   - Display progress and results

## Examples

### Example 1: Add "Production" tag to all applications

**tags.json:**
```json
{
    "applications_id": [""],
    "tags": ["Production"],
    "tags_remove": []
}
```

**specific_apps.csv:** (empty or doesn't exist)

**Result:** Adds "Production" tag to all applications in your organization

### Example 2: Add tags to specific applications only

**tags.json:**
```json
{
    "applications_id": [""],
    "tags": ["WebApp"],
    "tags_remove": []
}
```

**specific_apps.csv:**
```csv
00000000-0000-0000-0000-000000000000
00000000-0000-0000-0000-000000000001
```

**Result:** Adds "WebApp" tag to only the two specified applications

### Example 3: Add different tags to different applications

**tags.json:**
```json
{
    "applications_id": [""],
    "tags": ["Default"],
    "tags_remove": []
}
```

**specific_apps.csv:**
```csv
00000000-0000-0000-0000-000000000000,CriticalApp,Production
00000000-0000-0000-0000-000000000001,InternalTool,Development
```

**Result:** 
- First app gets "CriticalApp" and "Production" tags (tags.json is ignored)
- Second app gets "InternalTool" and "Development" tags (tags.json is ignored)

### Example 4: Remove tags from all applications

**tags.json:**
```json
{
    "applications_id": [""],
    "tags": [],
    "tags_remove": ["Test", "Deprecated"]
}
```

**specific_apps.csv:** (empty or doesn't exist)

**Result:** Removes "Test" and "Deprecated" tags from all applications

## Troubleshooting

- **File not found errors:** Ensure `tags.json` exists in the `app-add-label` directory
- **API errors:** Verify your credentials in the `.creds` file are correct
- **No applications processed:** Check that your `specific_apps.csv` format is correct and app IDs are valid

## Notes

- Application IDs can be found in the Contrast UI or via the API
- Tags are case-sensitive
- The script will display detailed progress information as it processes applications
- All API responses are logged for debugging purposes