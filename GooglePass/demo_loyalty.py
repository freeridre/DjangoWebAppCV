#
# Copyright 2022 Google Inc. All rights reserved.
#
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
#

# [START setup]
# [START imports]
import json
import os
import uuid

from google.auth.transport.requests import AuthorizedSession
from google.oauth2.service_account import Credentials
from google.auth import jwt, crypt
import logging
logger = logging.getLogger(__name__)
# [END imports]


class DemoLoyalty:
    """Demo class for creating and managing Loyalty cards in Google Wallet.

    Attributes:
        key_file_path: Path to service account key file from Google Cloud
            Console. Environment variable: GOOGLE_APPLICATION_CREDENTIALS.
        base_url: Base URL for Google Wallet API requests.
    """

    def __init__(self):
        self.key_file_path = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS',
                                            '/path/to/key.json')
        self.base_url = 'https://walletobjects.googleapis.com/walletobjects/v1'
        self.batch_url = 'https://walletobjects.googleapis.com/batch'
        self.class_url = f'{self.base_url}/loyaltyClass'
        self.object_url = f'{self.base_url}/loyaltyObject'

        # Set up authenticated client
        self.auth()

    # [END setup]

    # [START auth]
    def auth(self):
        """Create authenticated HTTP client using a service account file."""
        self.credentials = Credentials.from_service_account_file(
            self.key_file_path,
            scopes=['https://www.googleapis.com/auth/wallet_object.issuer'])

        self.http_client = AuthorizedSession(self.credentials)

    # [END auth]

    # [START createClass]
    def create_class(self, issuer_id: str, class_suffix: str) -> str:
        """Create a class.

        Args:
            issuer_id (str): The issuer ID being used for this request.
            class_suffix (str): Developer-defined unique ID for this pass class.

        Returns:
            The pass class ID: f"{issuer_id}.{class_suffix}"
        """

        # Check if the class exists
        response = self.http_client.get(
            url=f'{self.class_url}/{issuer_id}.{class_suffix}')

        if response.status_code == 200:
            print(f'Class {issuer_id}.{class_suffix} already exists!')
            return f'{issuer_id}.{class_suffix}'
        elif response.status_code != 404:
            # Something else went wrong...
            print(response.text)
            return f'{issuer_id}.{class_suffix}'

        # See link below for more information on required properties
        # https://developers.google.com/wallet/retail/loyalty-cards/rest/v1/loyaltyclass
        new_class = {
            'id': f'{issuer_id}.{class_suffix}',
            'issuerName': 'Issuer name',
            'reviewStatus': 'UNDER_REVIEW',
            'programName': 'Program name',
            'programLogo': {
                'sourceUri': {
                    'uri':
                        'http://farm8.staticflickr.com/7340/11177041185_a61a7f2139_o.jpg'
                },
                'contentDescription': {
                    'defaultValue': {
                        'language': 'en-US',
                        'value': 'Logo description'
                    }
                }
            }
        }

        response = self.http_client.post(url=self.class_url, json=new_class)

        print('Class insert response')
        print(response.text)

        return response.json().get('id')

    # [END createClass]

    # [START updateClass]
    def update_class(self, issuer_id: str, class_suffix: str) -> str:
        """Update a class.

        **Warning:** This replaces all existing class attributes!

        Args:
            issuer_id (str): The issuer ID being used for this request.
            class_suffix (str): Developer-defined unique ID for this pass class.

        Returns:
            The pass class ID: f"{issuer_id}.{class_suffix}"
        """

        # Check if the class exists
        response = self.http_client.get(
            url=f'{self.class_url}/{issuer_id}.{class_suffix}')

        if response.status_code == 404:
            print(f'Class {issuer_id}.{class_suffix} not found!')
            return f'{issuer_id}.{class_suffix}'
        elif response.status_code != 200:
            # Something else went wrong...
            print(response.text)
            return f'{issuer_id}.{class_suffix}'

        # Class exists
        updated_class = response.json()

        # Update the class by adding a homepage
        updated_class['homepageUri'] = {
            'uri': 'https://developers.google.com/wallet',
            'description': 'Homepage description'
        }

        # Note: reviewStatus must be 'UNDER_REVIEW' or 'DRAFT' for updates
        updated_class['reviewStatus'] = 'UNDER_REVIEW'

        response = self.http_client.put(
            url=f'{self.class_url}/{issuer_id}.{class_suffix}',
            json=updated_class)

        print('Class update response')
        print(response.text)

        return response.json().get('id')

    # [END updateClass]

    # [START patchClass]
    def patch_class(self, issuer_id: str, class_suffix: str) -> str:
        """Patch a class.

        The PATCH method supports patch semantics.

        Args:
            issuer_id (str): The issuer ID being used for this request.
            class_suffix (str): Developer-defined unique ID for this pass class.

        Returns:
            The pass class ID: f"{issuer_id}.{class_suffix}"
        """

        # Check if the class exists
        response = self.http_client.get(
            url=f'{self.class_url}/{issuer_id}.{class_suffix}')

        if response.status_code == 404:
            print(f'Class {issuer_id}.{class_suffix} not found!')
            return f'{issuer_id}.{class_suffix}'
        elif response.status_code != 200:
            # Something else went wrong...
            print(response.text)
            return f'{issuer_id}.{class_suffix}'

        # Patch the class by adding a homepage
        patch_body = {
            'homepageUri': {
                'uri': 'https://developers.google.com/wallet',
                'description': 'Homepage description'
            },

            # Note: reviewStatus must be 'UNDER_REVIEW' or 'DRAFT' for patches
            'reviewStatus': 'UNDER_REVIEW'
        }

        response = self.http_client.patch(
            url=f'{self.class_url}/{issuer_id}.{class_suffix}', json=patch_body)

        print('Class patch response')
        print(response.text)

        return response.json().get('id')

    # [END patchClass]

    # [START addMessageClass]
    def add_class_message(self, issuer_id: str, class_suffix: str, header: str,
                          body: str) -> str:
        """Add a message to a pass class.

        Args:
            issuer_id (str): The issuer ID being used for this request.
            class_suffix (str): Developer-defined unique ID for this pass class.
            header (str): The message header.
            body (str): The message body.

        Returns:
            The pass class ID: f"{issuer_id}.{class_suffix}"
        """

        # Check if the class exists
        response = self.http_client.get(
            url=f'{self.class_url}/{issuer_id}.{class_suffix}')

        if response.status_code == 404:
            print(f'Class {issuer_id}.{class_suffix} not found!')
            return f'{issuer_id}.{class_suffix}'
        elif response.status_code != 200:
            # Something else went wrong...
            print(response.text)
            return f'{issuer_id}.{class_suffix}'

        response = self.http_client.post(
            url=f'{self.class_url}/{issuer_id}.{class_suffix}/addMessage',
            json={'message': {
                'header': header,
                'body': body
            }})

        print('Class addMessage response')
        print(response.text)

        return response.json().get('id')

    # [END addMessageClass]

    # [START createObject]
    def create_object(self, issuer_id: str, class_suffix: str,
                      object_suffix: str, user_name: str, pay_load: str, date_time: str, access_tier: str) -> str:
        """Create an object.

        Args:
            issuer_id (str): The issuer ID being used for this request.
            class_suffix (str): Developer-defined unique ID for the pass class.
            object_suffix (str): Developer-defined unique ID for the pass object.

        Returns:
            The pass object ID: f"{issuer_id}.{object_suffix}"
        """

        # Check if the object exists
        response = self.http_client.get(
            url=f'{self.object_url}/{issuer_id}.{object_suffix}')

        if response.status_code == 200:
            print(f'Object {issuer_id}.{object_suffix} already exists!')
            print(response.text)
            logger.debug("[DEBUG]: Object Already exists.")
            return f'{issuer_id}.{object_suffix}'
        elif response.status_code != 404:
            # Something else went wrong...
            print(response.text)
            logger.debug("[DEBUG]: Something went wrong.")
            return f'{issuer_id}.{object_suffix}'

        # See link below for more information on required properties
        # https://developers.google.com/wallet/retail/loyalty-cards/rest/v1/loyaltyobject
        new_object = {
            'id': f'{issuer_id}.{object_suffix}',
            'classId': f'{issuer_id}.{class_suffix}',
            'state': 'ACTIVE',
            "textModulesData": [
                {
                    "header": "NAME",
                    "body": f"{user_name}",
                    "id": "username"
                },
                {
                    "header": "UID",
                    "body": f"{pay_load.upper()}",
                    "id": "uid"
                },
                {
                    "header": "CREATED",
                    "body": f"{date_time}",
                    "id": "create"
                },
                {
                    "header": "STATUS",
                    "body": "ACTIVE",
                    "id": "status"
                },
                {
                    "header": "ACCESS TIER",
                    "body": f"{access_tier}",
                    "id": "access_level"
                }
            ],
            "smartTapRedemptionValue": f"{pay_load}",
            "passConstraints": {
                "screenshotEligibility": "INELIGIBLE",
                "nfcConstraint": [
                    "BLOCK_PAYMENT",
                    "BLOCK_CLOSED_LOOP_TRANSIT"
                ]
            }
        }

        # Create the object
        response = self.http_client.post(url=self.object_url, json=new_object)

        print('Object insert response')
        print(response.text)
        logger.debug(f"[DEBUG]: Response ID: {response.json().get('id')}")
        return response.json().get('id')

    # [END createObject]

    # [START updateObject]
    def update_object(self, issuer_id: str, object_suffix: str) -> str:
        """Update an object.

        **Warning:** This replaces all existing object attributes!

        Args:
            issuer_id (str): The issuer ID being used for this request.
            object_suffix (str): Developer-defined unique ID for the pass object.

        Returns:
            The pass object ID: f"{issuer_id}.{object_suffix}"
        """

        # Check if the object exists
        response = self.http_client.get(
            url=f'{self.object_url}/{issuer_id}.{object_suffix}')

        if response.status_code == 404:
            print(f'Object {issuer_id}.{object_suffix} not found!')
            return f'{issuer_id}.{object_suffix}'
        elif response.status_code != 200:
            # Something else went wrong...
            print(response.text)
            return f'{issuer_id}.{object_suffix}'

        # Object exists
        updated_object = response.json()

        # Update the object by adding a link
        new_link = {
            'uri': 'https://developers.google.com/wallet',
            'description': 'New link description'
        }
        if not updated_object.get('linksModuleData'):
            updated_object['linksModuleData'] = {'uris': []}
        updated_object['linksModuleData']['uris'].append(new_link)

        response = self.http_client.put(
            url=f'{self.object_url}/{issuer_id}.{object_suffix}',
            json=updated_object)

        print('Object update response')
        print(response.text)

        return response.json().get('id')

    # [END updateObject]

    # [START patchObject]
    def patch_object(self, issuer_id: str, object_suffix: str, new_smart_tap_value: str, new_t_value_1: str, new_t_value_2: str, txtm_1: str, txtm_2: str) -> str:
        """Patch an object.

        Args:
            issuer_id (str): The issuer ID being used for this request.
            object_suffix (str): Developer-defined unique ID for the pass object.

        Returns:
            The pass object ID: f"{issuer_id}.{object_suffix}"
        """

        # Check if the object exists
        response = self.http_client.get(
            url=f'{self.object_url}/{issuer_id}.{object_suffix}')

        if response.status_code == 404:
            print(f'Object {issuer_id}.{object_suffix} not found!')
            return f'{issuer_id}.{object_suffix}'
        elif response.status_code != 200:
            # Something else went wrong...
            print(response.text)
            return f'{issuer_id}.{object_suffix}'

        # Object exists
        existing_object = response.json()

        # Patch the object by adding a link
        patch_body = {
            'smartTapRedemptionValue': new_smart_tap_value,
            # Assuming we want to update or add a text module data entry for tValue
            'textModulesData': existing_object.get('textModulesData', []),
        }

        # Update or add the specified text module data entry
        found = False
        for module in patch_body['textModulesData']:
            if module.get('id') == txtm_1:  # Assuming 'uid' is used as an id within textModulesData
                module['body'] = new_t_value_1  # Update the body of the module
            if module.get('id') == txtm_2:  # Assuming 'uid' is used as an id within textModulesData
                module['body'] = new_t_value_2  # Update the body of the module

        response = self.http_client.patch(url=f'{self.object_url}/{issuer_id}.{object_suffix}', json=patch_body)

        print('Object patch response')
        print(response.text)

        return response.json().get('id'), "OK"

    # [END patchObject]

    # [START expireObject]
    def expire_object(self, issuer_id: str, object_suffix: str) -> str:
        """Expire an object.

        Sets the object's state to Expired. If the valid time interval is
        already set, the pass will expire automatically up to 24 hours after.

        Args:
            issuer_id (str): The issuer ID being used for this request.
            object_suffix (str): Developer-defined unique ID for the pass object.

        Returns:
            The pass object ID: f"{issuer_id}.{object_suffix}"
        """

        # Check if the object exists
        response = self.http_client.get(
            url=f'{self.object_url}/{issuer_id}.{object_suffix}')

        if response.status_code == 404:
            print(f'Object {issuer_id}.{object_suffix} not found!')
            return f'{issuer_id}.{object_suffix}'
        elif response.status_code != 200:
            # Something else went wrong...
            print(response.text)
            return f'{issuer_id}.{object_suffix}'

        # Patch the object, setting the pass as expired
        patch_body = {'state': 'EXPIRED'}

        response = self.http_client.patch(
            url=f'{self.object_url}/{issuer_id}.{object_suffix}',
            json=patch_body)

        print('Object expiration response')
        print(response.text)

        return response.json().get('id')

    # [END expireObject]

    # [START addMessageObject]
    def add_object_message(self, issuer_id: str, object_suffix: str,
                           header: str, body: str) -> str:
        """Add a message to a pass object.

        Args:
            issuer_id (str): The issuer ID being used for this request.
            object_suffix (str): Developer-defined unique ID for this pass object.
            header (str): The message header.
            body (str): The message body.

        Returns:
            The pass class ID: f"{issuer_id}.{class_suffix}"
        """

        # Check if the object exists
        response = self.http_client.get(
            url=f'{self.object_url}/{issuer_id}.{object_suffix}')

        if response.status_code == 404:
            print(f'Object {issuer_id}.{object_suffix} not found!')
            return f'{issuer_id}.{object_suffix}'
        elif response.status_code != 200:
            # Something else went wrong...
            print(response.text)
            return f'{issuer_id}.{object_suffix}'

        response = self.http_client.post(
            url=f'{self.object_url}/{issuer_id}.{object_suffix}/addMessage',
            json={'message': {
                'header': header,
                'body': body
            }})

        print('Object addMessage response')
        print(response.text)

        return response.json().get('id')

    # [END addMessageObject]

    # [START jwtNew]
    def create_jwt_new_objects(self, issuer_id: str, class_suffix: str,
                               object_suffix: str, user_name: str, pay_load: str, date_time: str) -> str:
        """Generate a signed JWT that creates a new pass class and object.

        When the user opens the "Add to Google Wallet" URL and saves the pass to
        their wallet, the pass class and object defined in the JWT are
        created. This allows you to create multiple pass classes and objects in
        one API call when the user saves the pass to their wallet.

        Args:
            issuer_id (str): The issuer ID being used for this request.
            class_suffix (str): Developer-defined unique ID for the pass class.
            object_suffix (str): Developer-defined unique ID for the pass object.

        Returns:
            An "Add to Google Wallet" link.
        """

        # See link below for more information on required properties
        # https://developers.google.com/wallet/retail/loyalty-cards/rest/v1/loyaltyclass
        new_class = {
            'programName': 'Rozmaring Street 5.',
            'programLogo': {
                'sourceUri': {
                    'uri':
                        'https://senitysecuritysystems.com/static/images/passes/google/logo.png'
                },
                'contentDescription': {
                    'defaultValue': {
                        'language': 'en-US',
                        'value': 'Logo description'
                    }
                }
            },
            'classTemplateInfo': {
                "cardTemplateOverride": {
                    "cardRowTemplateInfos": [
                        {
                            "oneItem": {
                                "item": {
                                    "firstValue": {"fields": [{"fieldPath": "object.textModulesData['username']"}]},
                                    "secondValue": {"fields": [{"fieldPath": "object.textModulesData['access_level']"}]}
                                }
                            }
                        },
                        {
                            "oneItem": {
                                "item": {
                                    "firstValue": {"fields": [{"fieldPath": "object.textModulesData['uid']"}]}}
                                }
                        },
                        {
                            "oneItem": {
                                "item": {"firstValue": {"fields": [{"fieldPath": "object.textModulesData['create']"}]}}
                                }
                        },
                        {
                            "oneItem": {
                                "item": {"firstValue": {"fields": [{"fieldPath": "object.textModulesData['status']"}]}}
                                }
                        }
                    ]
                }
            },
            'id': f'{issuer_id}.{class_suffix}',
            'issuerName': 'ACCESS CARD',
            "homepageUri": {
                "uri": "https://senitysecuritysystems.com",
                "description": "Senity's website",
                "id": "2813"
            },
            "locations": [
                {
                    "latitude": 47.47313,
                    "longitude": 19.01918
                }
            ],
            'reviewStatus': 'UNDER_REVIEW',
            "redemptionIssuers": [
                f"{issuer_id}"
            ],
            "countryCode": "HU",
            "enableSmartTap": True,
            "hexBackgroundColor": "#0a2f57",
            "multipleDevicesAndHoldersAllowedStatus": "ONE_USER_ALL_DEVICES",
            "callbackOptions": {
                "url": "https://senitysecuritysystems.com/UserHandler/google/api/passes/"
            },
            'securityAnimation': {
                'animationType': 'FOIL_SHIMMER'
            },
            "viewUnlockRequirement": "UNLOCK_REQUIRED_TO_VIEW",
        }
        """'heroImage': {
            'sourceUri': {
                'uri':
                    'https://senitysecuritysystems.com/static/images/passes/google/hero.png'
            },
            'contentDescription': {
                'defaultValue': {
                    'language': 'en-US',
                    'value': 'Hero image description'
                }
            }
        },"""

        # See link below for more information on required properties
        # https://developers.google.com/wallet/retail/loyalty-cards/rest/v1/loyaltyobject
        new_object = {
            'id': f'{issuer_id}.{object_suffix}',
            'classId': f'{issuer_id}.{class_suffix}',
            'state': 'ACTIVE',
            "textModulesData": [
                {
                    "header": "NAME",
                    "body": f"{user_name}",
                    "id": "username"
                },
                {
                    "header": "UID",
                    "body": f"{pay_load.upper()}",
                    "id": "uid"
                },
                {
                    "header": "CREATED",
                    "body": f"{date_time}",
                    "id": "create"
                },
                {
                    "header": "STATUS",
                    "body": "ACTIVE",
                    "id": "status"
                },
                {
                    "header": "ACCESS TIER",
                    "body": "STANDARD",
                    "id": "access_level"
                }
            ],
            "smartTapRedemptionValue": f"{pay_load}",
            "passConstraints": {
                "screenshotEligibility": "INELIGIBLE",
                "nfcConstraint": [
                    "BLOCK_PAYMENT",
                    "BLOCK_CLOSED_LOOP_TRANSIT"
                ]
            }
        }

        # Create the JWT claims
        claims = {
            'iss': self.credentials.service_account_email,
            'aud': 'google',
            'origins': ['https://senitysecuritysystems.com'],
            'typ': 'savetowallet',
            'payload': {
                # The listed classes and objects will be created
                'loyaltyClasses': [new_class],
                'loyaltyObjects': [new_object]
            },
        }

        # The service account credentials are used to sign the JWT
        signer = crypt.RSASigner.from_service_account_file(self.key_file_path)
        token = jwt.encode(signer, claims).decode('utf-8')

        return f'https://pay.google.com/gp/v/save/{token}', token

    # [END jwtNew]

    def decode_jwt(token):
        try:
            # Decode token. Without verification as the secret key is not provided
            decoded = jwt.decode(token, options={"verify_signature": False})
            return decoded
        except jwt.PyJWTError as e:
            # Handle decoding error (e.g., token is expired or invalid format)
            print("An error occurred:", e)
            return None

    # [START jwtExisting]
    def create_jwt_existing_objects(self, issuer_id: str, object_suffix: str, class_suffix: str) -> str:
        """Generate a signed JWT that references an existing pass object.

        When the user opens the "Add to Google Wallet" URL and saves the pass to
        their wallet, the pass objects defined in the JWT are added to the
        user's Google Wallet app. This allows the user to save multiple pass
        objects in one API call.

        The objects to add must follow the below format:

        {
            'id': 'ISSUER_ID.OBJECT_SUFFIX',
            'classId': 'ISSUER_ID.CLASS_SUFFIX'
        }

        Args:
            issuer_id (str): The issuer ID being used for this request.

        Returns:
            An "Add to Google Wallet" link
        """

        # Multiple pass types can be added at the same time
        # At least one type must be specified in the JWT claims
        # Note: Make sure to replace the placeholder class and object suffixes
        """
        # Event tickets
        'eventTicketObjects': [{
            'id': f'{issuer_id}.EVENT_OBJECT_SUFFIX',
            'classId': f'{issuer_id}.EVENT_CLASS_SUFFIX'
        }],

        # Boarding passes
        'flightObjects': [{
            'id': f'{issuer_id}.FLIGHT_OBJECT_SUFFIX',
            'classId': f'{issuer_id}.FLIGHT_CLASS_SUFFIX'
        }],
        # Offers
        'offerObjects': [{
            'id': f'{issuer_id}.OFFER_OBJECT_SUFFIX',
            'classId': f'{issuer_id}.OFFER_CLASS_SUFFIX'
        }],
        # Generic passes
        'genericObjects': [{
            'id': f'{issuer_id}.GENERIC_OBJECT_SUFFIX',
            'classId': f'{issuer_id}.GENERIC_CLASS_SUFFIX'
        }],

        # Gift cards
        'giftCardObjects': [{
            'id': f'{issuer_id}.GIFT_CARD_OBJECT_SUFFIX',
            'classId': f'{issuer_id}.GIFT_CARD_CLASS_SUFFIX'
        }],
        # Transit passes
        'transitObjects': [{
            'id': f'{issuer_id}.TRANSIT_OBJECT_SUFFIX',
            'classId': f'{issuer_id}.TRANSIT_CLASS_SUFFIX'
        }]
        """
        objects_to_add = {
            # Loyalty cards
            'loyaltyObjects': [{
                'id': f'{object_suffix}',
                'classId': f'{issuer_id}.{class_suffix}'
            }],

        }
        logger.debug(f"[DEBUG]: objects_to_add: {objects_to_add}")

        # Create the JWT claims
        claims = {
            'iss': self.credentials.service_account_email,
            'aud': 'google',
            'origins': ['https://senitysecuritysystems.com'],
            'typ': 'savetowallet',
            'payload': objects_to_add
        }

        # The service account credentials are used to sign the JWT
        signer = crypt.RSASigner.from_service_account_file(self.key_file_path)
        token = jwt.encode(signer, claims).decode('utf-8')

        print('Add to Google Wallet link')
        print(f'https://pay.google.com/gp/v/save/{token}')
        logger.debug(f"[DEBUG]: JWT: https://pay.google.com/gp/v/save/{token}")
        logger.debug(f"[DEBUG]: Token: {token}")
        return f'https://pay.google.com/gp/v/save/{token}', token

    # [END jwtExisting]

    # [START batch]
    def batch_create_objects(self, issuer_id: str, class_suffix: str):
        """Batch create Google Wallet objects from an existing class.

        The request body will be a multiline string. See below for information.

        https://cloud.google.com/compute/docs/api/how-tos/batch#example

        Args:
            issuer_id (str): The issuer ID being used for this request.
            class_suffix (str): Developer-defined unique ID for this pass class.
        """
        data = ''

        # Example: Generate three new pass objects
        for _ in range(3):
            # Generate a random object suffix
            object_suffix = str(uuid.uuid4()).replace('[^\\w.-]', '_')

            # See link below for more information on required properties
            # https://developers.google.com/wallet/retail/loyalty-cards/rest/v1/loyaltyobject
            batch_object = {
                'id': f'{issuer_id}.{object_suffix}',
                'classId': f'{issuer_id}.{class_suffix}',
                'state': 'ACTIVE',
                'heroImage': {
                    'sourceUri': {
                        'uri':
                            'https://farm4.staticflickr.com/3723/11177041115_6e6a3b6f49_o.jpg'
                    },
                    'contentDescription': {
                        'defaultValue': {
                            'language': 'en-US',
                            'value': 'Hero image description'
                        }
                    }
                },
                'textModulesData': [{
                    'header': 'Text module header',
                    'body': 'Text module body',
                    'id': 'TEXT_MODULE_ID'
                }],
                'linksModuleData': {
                    'uris': [{
                        'uri': 'http://maps.google.com/',
                        'description': 'Link module URI description',
                        'id': 'LINK_MODULE_URI_ID'
                    }, {
                        'uri': 'tel:6505555555',
                        'description': 'Link module tel description',
                        'id': 'LINK_MODULE_TEL_ID'
                    }]
                },
                'imageModulesData': [{
                    'mainImage': {
                        'sourceUri': {
                            'uri':
                                'http://farm4.staticflickr.com/3738/12440799783_3dc3c20606_b.jpg'
                        },
                        'contentDescription': {
                            'defaultValue': {
                                'language': 'en-US',
                                'value': 'Image module description'
                            }
                        }
                    },
                    'id': 'IMAGE_MODULE_ID'
                }],
                'barcode': {
                    'type': 'QR_CODE',
                    'value': 'QR code'
                },
                'locations': [{
                    'latitude': 37.424015499999996,
                    'longitude': -122.09259560000001
                }],
                'accountId': 'Account id',
                'accountName': 'Account name',
                'loyaltyPoints': {
                    'label': 'Points',
                    'balance': {
                        'int': 800
                    }
                }
            }

            data += '--batch_createobjectbatch\n'
            data += 'Content-Type: application/json\n\n'
            data += 'POST /walletobjects/v1/loyaltyObject/\n\n'

            data += json.dumps(batch_object) + '\n\n'

        data += '--batch_createobjectbatch--'

        # Invoke the batch API calls
        response = self.http_client.post(
            url=self.batch_url, # https://walletobjects.googleapis.com/batch
            data=data,
            headers={
                # `boundary` is the delimiter between API calls in the batch request
                'Content-Type':
                    'multipart/mixed; boundary=batch_createobjectbatch'
            })

        print('Batch insert response')
        print(response.content.decode('UTF-8'))

    # [END batch]
