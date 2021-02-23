# Sentry Mattermost
A plugin for Sentry to enable notifications to Mattermost Open Source Chat.
This is based in the sentry-slack plugin: https://github.com/getsentry/sentry-slack

![Example](example.png)

# Usage
Install with pip and enable the plugin in a Sentry Project:

    pip install sentry_mattermost_reformed

Or just add 'sentry_mattermost_reformed' to requirements.txt

Configure Mattermost:
- Create an Incoming Webhook
- Enable override usernames and profile picture icons in System Console Integrations
