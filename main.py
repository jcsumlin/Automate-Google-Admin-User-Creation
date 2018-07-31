import webbrowser
import urllib.request
import httplib2
from apiclient.discovery import build
from oauth2client.client import flow_from_clientsecrets
from oauth2client.file import Storage
from simple_salesforce import Salesforce
import googleapiclient
import configparser

config = configparser.ConfigParser()
config.read('auth.ini')
SANDBOX = config.get('auth', 'sandbox')

def str2bool(v):
    if v.lower in ("yes", "true", "t", "1"):
        SANDBOX = True
    elif v.lower in ("no", "false", "f", "0"):
        SANDBOX = False
    else:
        print("Invalid Sandbox Value!")
        exit()
    return SANDBOX

str2bool(SANDBOX)

def login_to_salesforce(sandbox=True):
    # iKlXytmUw85PBaXJjHEaSvxPc - REAL
    # 2mwSaEMs50IWXe8DnYBy3ImhZ - SANDBOX
    if sandbox is True:
        sf = Salesforce(username=config.get('auth', 'salesforce_username'),
                        domain='test',
                        password=config.get('auth', 'salesforce_password'),
                        security_token=config.get('auth', 'salesforce_token_sandbox'))
        return sf
    elif sandbox is False:
        sf = Salesforce(username=config.get('auth', 'salesforce_username'),
                        password=config.get('auth', 'salesforce_password'),
                        security_token=config.get('auth', 'salesforce_token_live'))
        return sf

def check_for_new_user(sf):
    users = sf.query("SELECT Id, Name, Email, Department, Title, FirstName, LastName, Phone FROM User WHERE New__c=TRUE")
    if users['totalSize'] > 0:
        print("%s record(s) found in SF matching the criteria!" % users['totalSize'])
        return users['records']
    else:
        return False



def create_email(SF_Results):
    for user in SF_Results:
        if user['Phone'] is not None:
            phone_number = str(user['Phone'])
        else:
            phone_number = ""
        data = {
            "name": {
                "familyName": user['FirstName'],
                "givenName": user['LastName'],
                "fullName": user['Name']
            },
            "organizations": [
                {
                    "name": "Payscape",
                    "title": user['Title'],
                    "primary": True,
                    "customType": "",
                    "description": user['Title'],
                    "department": user['Department']
                }
            ],
            "phones": [
                {
                    "value": phone_number,
                    "type": "work"
                }
            ],
            "primaryEmail": user['Email'],
            "password": "ilovepayscape",
            "changePasswordAtNextLogin": True
        }
        try:
            google_api_create_user(check_stored_token(), data)
        except:
            google_api_create_user(google_api_authorize(), data)
        update_user_record(user['Id'])
        print("User \"%s\" has been created Google Admin! And the SF record has been updated!" % user['Name'])

def update_user_record(user_id):
    try:
        user = login_to_salesforce(sandbox=SANDBOX).User.update(user_id, {'New__c': False, 'gmailCreated__c': True})
        return user
    except Exception as e:
        print(e)


def check_stored_token():
    storage = Storage('token.json')
    credentials = storage.get()
    http = httplib2.Http()
    http = credentials.authorize(http)
    service = build('admin', 'directory_v1', http=http)
    return service

def google_api_authorize():
    flow = flow_from_clientsecrets('client_secret.json',
                               scope='https://www.googleapis.com/auth/admin.directory.user',
                               redirect_uri='urn:ietf:wg:oauth:2.0:oob')

    auth_uri = flow.step1_get_authorize_url()
    webbrowser.open(auth_uri)
    auth_code = input("\nAuthorization Code >>> ") #
    credentials = flow.step2_exchange(auth_code)
    storage = Storage('token.json')
    http = httplib2.Http()
    http = credentials.authorize(http)
    service = build('admin', 'directory_v1', http=http)

    storage.put(credentials)
    return service
def google_api_create_user(service, data):
    # Call the Admin SDK Directory API
    results = service.users().insert(body=data).execute()
    return results


if __name__ == '__main__':
    try:
        SF_Results = check_for_new_user(login_to_salesforce(sandbox=SANDBOX))
        if SF_Results is not False:
            create_email(SF_Results)
        else:
            print("No user matching the criteria was found!")
    except googleapiclient.errors.HttpError as err:
        print(err)
    except Exception as e:
        print(e)
