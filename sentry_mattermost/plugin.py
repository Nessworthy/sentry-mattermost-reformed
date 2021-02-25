# Copyright (c) 2015 NDrive SA
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import json
import urllib.request
import urllib.parse
import operator

from django import forms
from django.db.models import Q
from sentry import tagstore
from sentry.plugins.bases import notify

import sentry_mattermost

LEVEL_TO_COLOR = {
    "debug": "cfd3da",
    "info": "2788ce",
    "warning": "f18500",
    "error": "f43f20",
    "fatal": "d20f2a",
}


class PayloadFactory:
    
    @classmethod
    def _get_tags(cls, event):
        tag_list = event.tags
        if not tag_list:
            return ()

        return (
            (tagstore.get_tag_key_label(k), tagstore.get_tag_value_label(k, v)) for k, v in tag_list
        )
    
    @classmethod
    def color_for_event(cls, event):
        return "#" + LEVEL_TO_COLOR.get(event.get_tag("level"), "error")
    
    @classmethod
    def render_text(cls, params):
        template = "__{project}__\n__[{title}]({link})__ \n{culprit}\n"
        return template.format(**params)

    @classmethod
    def create(cls, plugin, notification):
        event = notification.event
        group = event.group
        project = group.project
        
        title = event.title
        culprit = group.culprit
        project_name = project.get_full_name()
        
        fields = []
        
        fields.append({"title": "Culprit", "value": culprit, "short": False})
        
        if plugin.get_option('include_rules', project):
            rules = []
            for rule in notification.rules:
                rule_link = (
                    f"/{group.organization.slug}/{project.slug}/settings/alerts/rules/{rule.id}/"
                )

                rule_link = absolute_uri(rule_link)
                rules.append((rule.label, rule_link))

            if rules:
                value = ", ".join("[{}]({})".format(*r) for r in rules)

                fields.append(
                    {"title": "Triggered By", "value": value, "short": False}
                )
        
        if plugin.get_option('include_tags', project):
            for tag_key, tag_value in cls._get_tags(event):
                key = tag_key.lower()
                std_key = tagstore.get_standardized_key(key)
                fields.append(
                    {
                        "title": tag_key,
                        "value": tag_value,
                        "short": True,
                    }
                )
        
        payload = {
            "username": "Sentry",
            "icon_url": "https://myovchev.github.io/sentry-slack/images/logo32.png", #noqa
            "attachments": [
                {
                    "fallback": "[%s] %s" % (project_name, title),
                    "title": title,
                    "title_link": group.get_absolute_url(params={"referrer": "mattermost"}),
                    "color": cls.color_for_event(event),
                    "fields": fields,
                    "author_name": "[%s] %s" % (project_name, title)
                }
            ],
            "message": ""
        }
        return payload


def request(url, payload):
    data = urllib.parse.urlencode({'payload': json.dumps(payload)}).encode('utf-8')
    
    req = urllib.request.Request(url, data)
    response = urllib.request.urlopen(req)
    return response.read()


class MattermostOptionsForm(notify.NotificationConfigurationForm):
    webhook = forms.URLField(
        help_text='Incoming Webhook URL',
        widget=forms.URLInput(attrs={'class': 'span8'})
    )
    include_rules = forms.BooleanField(
        help_text='Include triggering rules with notifications',
        required=False,
    )
    include_tags = forms.BooleanField(
        help_text='Include tags with notifications',
        required=False,
    )


class Mattermost(notify.NotificationPlugin):
    title = 'Mattermost'
    slug = 'mattermost'
    description = 'Enables notifications for Mattermost'
    version = sentry_mattermost.VERSION
    author = 'Sean Nessworthy'
    author_url = 'https://nessworthy.me'
    project_conf_form = MattermostOptionsForm

    def is_configured(self, project):
        return all((self.get_option(k, project) for k in ('webhook',)))

    def notify(self, notification, raise_exception=False):
        event = notification.event
        try:
            project = event.group.project
            if not self.is_configured(project):
                return

            webhook = self.get_option('webhook', project)
            payload = PayloadFactory.create(self, notification)
            return request(webhook, payload)
        except Exception as err:
            self.logger.info(
                "notification-plugin.notify-failed",
                extra={
                    "error": str(err),
                    "plugin": self.slug,
                    "project_id": event.group.project_id,
                    "organization_id": event.group.project.organization_id,
                },
            )
            if raise_exception:
                raise err
            return False
