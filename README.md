# Sesam Node Notification Manager

#### Sesam Node microservice to dynamically create and update notification settings for pipes on a given node

### :warning: DISCLAIMER! This service will add additional charges to your invoice. The service will create notfication rules for any pipes that match the given pattern. 

The rules expect a wildcard pattern to match pipe ids:
```
"pipes": ["*-endpoint"],
```
See full examples in the example config below.

### Example config

Prerequisites:
* A dedicated notification role must be created on the node. It should be created in the portal and must be called `notification-recipient`.
* All rules in the configuration must have a unique name.
* For the service to function, the `jwt` must have developer or higher privileges.


```json
{
  "_id": "notification-manager",
  "type": "system:microservice",
  "docker": {
    "environment": {
      "jwt": "$SECRET(notification_manager_jwt)",
      "node_endpoint": "https://123456.sesam.cloud/api",
      "interval": "1800",
      "notification_dataset": "manual-notification-notifier",
      "microservice_logging": true,
      "rules": [
        {
          "pipes": [
            "*"
          ],
          "template": {
            "description": "figure this out",
            "extra_rule_info": {
              "event_type": "pump-failed",
              "parameter": "original_error_message",
              "pattern": "*"
            },
            "name": "Any-error",
            "recipients": [
              {
                "id": "<SUBSCRIPTION_ID>_notification-recipient",
                "methods": ["email"],
                "type": "role"
              }
            ],
            "type": "pattern_match"
          }
        },
        {
          "pipes": ["*-endpoint"],
          "template": {
            "description": "Check all endpoint pipes for unknown serial number error.",
            "extra_rule_info": {
              "event_type": "pump-failed",
              "parameter": "original_error_message",
              "pattern": "Unknown serial number"
            },
            "name": "Unknown sn - All endpoints",
            "recipients": [
              {
                "id": "<SUBSCRIPTION_ID>_notification-recipient",
                "methods": ["email"],
                "type": "role"
              }
            ],
            "type": "pattern_match"
          }
        }
      ]
    },
    "image": "sesamcommunity/node-notification-manager",
    "port": 5000
  }
}
```
