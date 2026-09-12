# SOC Setup Guide — Step by Step

This guide walks through the complete setup of the Cloud SOC on AWS from scratch — from spinning up EC2 instances to a fully automated detection and response pipeline.

---

## Prerequisites

Before starting, make sure you have:

- An AWS account with EC2 access
- A Shuffler.io account (free tier works)
- API keys for: VirusTotal, Groq, Slack Bot
- A Slack workspace with a channel named `#soc-alerts` and `#soc-incidents`
- SSH key pair created in AWS (`.pem` file downloaded)

---

## Step 1 — AWS Infrastructure Setup

### Launch Wazuh Server EC2
- AMI: Ubuntu 24.04 LTS
- Instance type: `t3.medium` (minimum — Wazuh indexer is memory hungry)
- Storage: 50GB+ GP3
- Security Group inbound rules:

| Port | Protocol | Source | Purpose |
|------|----------|--------|---------|
| 22 | TCP | Your IP | SSH access |
| 443 | TCP | Your IP | Wazuh Dashboard |
| 1514 | TCP/UDP | Agent SG | Wazuh agent communication |
| 1515 | TCP | Agent SG | Wazuh agent enrollment |
| 55000 | TCP | Your IP | Wazuh API |

### Launch TheHive EC2
- AMI: Ubuntu 24.04 LTS
- Instance type: `t3.medium`
- Storage: 30GB GP3
- Security Group inbound rules:

| Port | Protocol | Source | Purpose |
|------|----------|--------|---------|
| 22 | TCP | Your IP | SSH access |
| 9000 | TCP | Your IP + Shuffle IPs | TheHive web UI and API |

### Launch Endpoint Agent EC2
- AMI: Ubuntu 24.04 LTS
- Instance type: `t3.small`
- Storage: 20GB GP3
- Security Group: allow outbound to Wazuh server on ports 1514/1515

> **Tip:** Allocate Elastic IPs to both the Wazuh server and TheHive instances. AWS reassigns public IPs on stop/start — Elastic IPs prevent this and save you from re-configuring agents every time.

---

## Step 2 — Wazuh SIEM Installation

SSH into the Wazuh server EC2 and run the official installer:

```bash
curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.12/config.yml
```

Edit `config.yml` to set your server's private IP, then run:

```bash
sudo bash wazuh-install.sh -a
```

This installs Wazuh Manager, Indexer, and Dashboard as a single-node cluster. Installation takes 5–10 minutes.

Once done, access the dashboard at `https://<EC2_PUBLIC_IP>`. Default credentials are printed at the end of the install output — save them.

### Apply Custom Configuration

Replace the default `ossec.conf` with the one from this repo:

```bash
sudo cp /path/to/wazuh/ossec.conf /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
```

### Add Custom Detection Rules

```bash
sudo cp /path/to/wazuh/custom_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

---

## Step 3 — Wazuh Agent Enrollment

SSH into the endpoint agent EC2 and install the Wazuh agent:

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
sudo apt install wazuh-agent
```

Enroll the agent with the Wazuh manager:

```bash
sudo WAZUH_MANAGER="<WAZUH_SERVER_PRIVATE_IP>" WAZUH_AGENT_NAME="endpoint-agent" apt install wazuh-agent
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

Verify the agent appears as **Active** in the Wazuh Dashboard under Agents.

---

## Step 4 — Suricata IDS Configuration

Install Suricata on the Wazuh server EC2:

```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata -y
```

Apply the configuration from this repo:

```bash
sudo cp /path/to/suricata/suricata.yaml /etc/suricata/suricata.yaml
sudo cp /path/to/suricata/local.rules /etc/suricata/rules/local.rules
```

Update Suricata rules (Emerging Threats Open ruleset):

```bash
sudo suricata-update
sudo systemctl restart suricata
```

Verify Suricata is running and detecting traffic:

```bash
sudo systemctl status suricata
sudo tail -f /var/log/suricata/fast.log
```

### Connect Suricata Alerts to Wazuh

Add the following to `/var/ossec/etc/ossec.conf` inside the `<ossec_config>` block (already included in the repo's `ossec.conf`):

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

Restart Wazuh manager:

```bash
sudo systemctl restart wazuh-manager
```

---

## Step 5 — TheHive Case Management

SSH into the TheHive EC2 and install Docker:

```bash
sudo apt update
sudo apt install docker.io docker-compose -y
sudo systemctl enable docker
sudo systemctl start docker
```

Deploy TheHive using the docker-compose file from this repo:

```bash
mkdir -p ~/thehive && cd ~/thehive
cp /path/to/thehive/docker-compose.yml .
sudo docker-compose up -d
```

Access TheHive at `http://<THEHIVE_EC2_PUBLIC_IP>:9000`

Default login: `admin@thehive.local` / `secret`

**Important:** Change the default password immediately after first login.

### Create an Organisation and API Key

1. Login as admin
2. Go to **Admin → Organisations → Create**
3. Name it `SOC`
4. Create a user inside that org with the `analyst` role
5. Generate an API key for that user — you will need this for Shuffle

---

## Step 6 — Shuffle SOAR Integration

### Import the Playbook

1. Go to [shuffler.io](https://shuffler.io) and log in
2. Navigate to **Workflows → Import**
3. Upload `shuffle/SOC_Full_Incident_Response_Playbook.json` from this repo
4. The workflow will import with all nodes intact

### Configure API Keys

In the imported workflow, update the following nodes with your actual API keys:

| Node | What to update |
|------|---------------|
| VirusTotal | API key in the HTTP header |
| Groq AI Triage | API key in Authorization header |
| TheHive Create Alert | API key + TheHive URL (`http://<THEHIVE_IP>:9000`) |
| Slack Notify | Bot token + channel names |

### Connect Wazuh Webhook

1. In Shuffle, click the **Webhook trigger** node
2. Copy the webhook URL shown
3. On the Wazuh server, add this to `/var/ossec/etc/ossec.conf`:

```xml
<integration>
  <name>shuffle</name>
  <hook_url>https://shuffler.io/api/v1/hooks/webhook_YOUR_WEBHOOK_ID</hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

4. Restart Wazuh: `sudo systemctl restart wazuh-manager`
5. Click **Start** on the Shuffle workflow

---

## Step 7 — API Integrations

### VirusTotal
- Sign up at [virustotal.com](https://virustotal.com)
- Go to your profile → API Key
- Free tier: 500 lookups/day — sufficient for a lab SOC

### Groq
- Sign up at [console.groq.com](https://console.groq.com)
- Create an API key
- Free tier is generous — no cost for this project

### Slack Bot
- Go to [api.slack.com/apps](https://api.slack.com/apps) → Create New App
- Add the `chat:write` OAuth scope
- Install to your workspace
- Copy the Bot User OAuth Token (`xoxb-...`)
- Invite the bot to `#soc-alerts` and `#soc-incidents`

---

## Step 8 — Validate the Pipeline

### Test 1 — SSH Brute Force Detection

From any machine, simulate failed SSH logins against the agent EC2:

```bash
for i in {1..10}; do ssh invalid_user@<AGENT_EC2_IP>; done
```

Expected: Wazuh fires rule 5763, Shuffle executes, TheHive case created, Slack notified.

### Test 2 — Suricata Network Alert

```bash
curl http://testmynids.org/uid/index.html
```

Expected: Suricata fires ET rule, alert appears in `fast.log`, Wazuh picks it up, pipeline executes.

### Test 3 — Manual Webhook Test

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"rule":{"level":10,"description":"Test Alert","id":"99999"},"agent":{"name":"test-agent"}}' \
  https://shuffler.io/api/v1/hooks/webhook_YOUR_WEBHOOK_ID
```

Expected: Shuffle workflow executes end-to-end.

---

## Troubleshooting

See the Troubleshooting section in the main [README](../README.md) for common issues with agents, Suricata, Shuffle, and TheHive.

---

## Author

Built by **Anudev** — [LinkedIn](https://www.linkedin.com/in/anudev-vp-b44423373) | [Medium](https://medium.com/@heyyanudev)
