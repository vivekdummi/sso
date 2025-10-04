import os
from yarl import URL

class Config:
    SECRET_KEY = 'your-secret-key'
    MYSQL_HOST = ''
    MYSQL_USER = ''
    MYSQL_PASSWORD = ''
    MYSQL_DB = ''

    # Preset API credentials
    API_TOKEN = "331e839c8bbb1"
    API_SECRET = "9ac6c4e22840079d763d0b2555743f506f39cfdb5e55"

    # PEM Key auth
    KEY_ID = "d31cfa"

    # Other configurations
    SALEM_DIALYSIS_DASHBOARD_ID = "f21114e8-8907-4106-9540-a58ddc7326ea"
    AIG_DASHBOARD_ID = "51aafeb6-acfc-4dc3-a574-5d02cfcdfedd"
    OVUM_ALL_DASHBOARD_ID = "90c1bee3-7775-4aef-b73f-bae0f62f1ad4"
    DCDC_DIALYSIS_DASHBOARD_ID = "b46e9818-a150-45be-89bf-62ca31f7e609"
    DCDC_ALL_DIALYSIS_DASHBOARD_ID = "b218313c-760b-4859-835c-ad7f16fec067"
    CLASS_DASHBOARD_ID = "132a8d4f-eee5-4c64-a7b0-dc3cc49fec29"
    REGENCY_DASHBOARD_ID = "396fb968-68ae-4611-ac50-1101aba6d443"
    SALEM_DASHBOARD_ID = "a8af45ab-5bad-49be-9b10-5f0aa95504d9"
    SPARSH_DASHBOARD_ID = "804f61e2-02c6-4288-b316-6249dddc6673"
    STAR_DASHBOARD_ID = "162983d9-1226-4ec6-a189-ee733d2f2cca"
    AGARWAL_DASHBOARD_ID = "316da0c6-c41f-4ca2-8ce6-ca39fe10b205"
    OVUM_KALYAN_NAGAR_DASHBOARD_ID = "6ede103a-2a86-419b-8e97-e1660f55c5ab"
    CMH_DASHBOARD_ID = "1ebb6f31-46d2-4c0f-85c3-2125aa89f062"
    EP_DASHBOARD_ID = "b8b410b4-5f8b-4a61-b9ed-bf856b24b998"
    CARE_DASHBOARD_ID = "ccc9756f-9ffb-48fc-87c1-b4cc3022d6a2"
    NEPHROPLUS_DASHBOARD_ID = "0d2db192-d773-45c9-8cfc-1f43b1c27ebb"
    SUPERSET_DOMAIN = "https://af8024b9.us2a.app.preset.io"
    PRESET_TEAM = "e4393dff"
    WORKSPACE_SLUG = "af8024b9"
    PRESET_BASE_URL = URL("https://api.app.preset.io/")
