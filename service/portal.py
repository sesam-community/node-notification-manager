
import requests
import logging

logger = logging.getLogger('NotificationManager')


class PortalConnection(object):

    BASE_URL = "https://portal.sesam.io/api/"

    def __init__(self, jwt):
        self.jwt = jwt

        headers = {
            "Authorization": f"Bearer {jwt}"
        }

        self.session = session = requests.Session()

        session.headers = headers

    def get_pipe_notification_rules(self, subscription_id, pipe_id):
        url = self.get_subscription_pipes_url(subscription_id) + f"{pipe_id}/notification-rules"
        resp = self.session.get(url)
        return resp.json()

    def add_pipe_notification_rule(self, subscription_id, pipe_id, rule):
        url = self.get_subscription_pipes_url(subscription_id) + f"{pipe_id}/notification-rules"
        resp = self.session.post(url, json=rule)
        if not resp.ok:
            logger.error("Failed to add notification rule for pipe '{pipe_id}'. Error: '{error}"
                         .format(pipe_id=pipe_id, error=resp.text))
        return resp.status_code

    def get_pipe_notification_rule(self, subscription_id, pipe_id, notification_rule_id):
        url = self.get_subscription_pipes_url(subscription_id) + f"{pipe_id}/notification-rules/{notification_rule_id}"
        resp = self.session.get(url)
        return resp.json()

    def update_pipe_notification_rule(self, subscription_id, pipe_id, notification_rule_id, rule_definition):
        url = self.get_subscription_pipes_url(subscription_id) + f"{pipe_id}/notification-rules/{notification_rule_id}"
        resp = self.session.put(url, json=rule_definition)
        if not resp.ok:
            logger.error("Failed to update notification rule for pipe '{pipe_id}'. Error: '{error}"
                         .format(pipe_id=pipe_id, error=resp.text))
        return resp.status_code

    def delete_pipe_notification_rule(self, subscription_id, pipe_id, notification_rule_id):
        url = self.get_subscription_pipes_url(subscription_id) + f"{pipe_id}/notification-rules/{notification_rule_id}"
        resp = self.session.delete(url)
        if not resp.ok:
            logger.error("Failed to update notification rule for pipe '{pipe_id}'. Error: '{error}"
                         .format(pipe_id=pipe_id, error=resp.text))
        return resp.status_code

    def get_subscription_pipes_url(self, subscription_id):
        return self.BASE_URL + f"subscriptions/{subscription_id}/pipes/"
