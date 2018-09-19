"""
Basic example of SMS and MMS response with Twilio.

Demostrates webhook validation, matching against a master number, and the
use of the Twilio Python helper library.
"""

from __future__ import print_function

import os
import json
import urllib
from twilio import twiml
from twilio.twiml.messaging_response import Message, MessagingResponse
from twilio.request_validator import RequestValidator
import boto3
from boto3.dynamodb.conditions import Key, Attr
from datetime import datetime
import uuid as myuuid

print(os.environ)
twilio_master_number = os.environ['MASTER_NUMBER']


def handler(event, context):
    resp = MessagingResponse()
    if u'twilioSignature' in event and u'Body' in event:

        form_parameters = {
            k: urllib.parse.unquote_plus(v) for k, v in event.items()
            if k != u'twilioSignature'
        }

        validator = RequestValidator(os.environ['AUTH_TOKEN'])
        request_valid = validator.validate(
            os.environ['REQUEST_URL'],
            form_parameters,
            event[u'twilioSignature']
        )
        request_valid = True
        if request_valid:
            
            s = form_parameters["Body"]
            print(s)
            data = ""
            try:
                json_acceptable_string = s.replace("'", "\"")
                data = json.loads(json_acceptable_string)
                print(data)
                
            except Exception as e:
                print(str(e))
            
            if data['request'] == "validateUser":
                try:
                    if not data['userName']:
                        resp.message("Error: Invalid Username")
                        return str(resp)
                    if not data['password']:
                        resp.message("Error: Invalid password")
                        return str(resp)
                        
                    client = boto3.client('cognito-idp')
                    response = client.admin_initiate_auth(
                        UserPoolId='us-east-2_zFJU1vK2t',
                        ClientId='4tco3thknv6ei9avcu32nhvhum',
                        AuthFlow='ADMIN_NO_SRP_AUTH',
                        AuthParameters={
                            'USERNAME': data['userName'],
                            'PASSWORD': data['password']
                        }
                    )
                    if 'AuthenticationResult' in response:
                        if 'AccessToken' in response['AuthenticationResult']:
                            resp.message( response['AuthenticationResult']['AccessToken'] )
                            return str(resp)
                except Exception as e:
                    resp.message("Error: " + str(e))
                    return str(resp)
                        
                resp.message("Error: Invalid credentials")
                return str(resp)
                    
                    
     # OVERDUE request.
            elif data['request'] == "overdue":
                if not data['libraryName']:
                    resp.message("Error: Invalid Libraryname")
                    return str(resp)
                    
                dynamodb = boto3.resource('dynamodb')
                table = dynamodb.Table('Book')
                
                response = table.scan(
                    FilterExpression=Attr('LibraryName').eq(data['libraryName']) & Attr('DateIssued').ne("-")
                )

                print(response)
                result = []
                if 'Items' in response:
                    for item in response['Items']:
                        print(item)
                        curDate = datetime.now().date()
                        print(item['DateIssued'])
                        bookDate = (datetime.strptime(item['DateIssued'], "%Y-%m-%d")).date()
                        if (curDate-bookDate).days >= 1:
                            result.append(item)
                print(result)
            res={}
            res['Items'] = result
            resp.message(json.dumps(res))
            return str(resp)
            
            
     # ADDBOOK request.
            elif data['request'] == "addBook":
                
                if ( not data.get('title') ):
                    resp.message("Error: Invalid Book Title")
                    return str(resp)
            
                if ( not data.get('barCode') ):
                    resp.message("Error: Invalid Book Barcode")
                    return str(resp)
                    
                if ( not data.get('firstName') ):
                    resp.message("Error: Invalid Author Firstname Field")
                    return str(resp)
                    
                    
                if ( not data.get('middleName') ):
                    resp.message("Error: Invalid Author MiddleName field")
                    return str(resp)
                    
                    
                if ( not data.get('lastName') ):
                    resp.message("Error: Invalid Author LastName Field")
                    return str(resp)
                    
                    
                if ( not data.get('libraryName') ):
                    resp.message("Error: Invalid LibraryName Field")
                    return str(resp)
                    
                    
                dynamodb = boto3.resource('dynamodb')
                table = dynamodb.Table('Book')
        
                try:
                    response = table.get_item(
                        Key = {
                            'BookBarcode': data.get('barcode')
                        }
                    )
                    if 'Item' in response:
                        book = response['Item']
                    else:
                        book = None
                    print("use",book)
                except ClientError as e:
                    book = None
        
                if(book != None):
                    resp.message("Error: Book already exist in database")
                    return str(resp)
        
                if (data.get('middleName')):
                    middleName = data.get('middleName')
                else:
                    middleName = "N/A"
                table.put_item(
                   Item={
                       
                       'Title': data.get('title'),
                       'FirstName': data.get('firstName'),
                       'MiddleName': middleName,
                       'LastName': data.get('lastName'),
                       'BookBarcode': data.get('barCode'),
                       'LibraryName': data.get('libraryName'),
                       'DateIssued': "-"
                    }
                )
                
                
                table = dynamodb.Table('LibraryBookDetails')
                
                response = table.get_item(
                    Key = {
                            'LibraryName': data.get('libraryName'),
                            'BookTitle': data.get('title')
                    }
                )
                if 'Item' in response:
                    table.update_item(
                        Key={
                            'LibraryName': data.get('libraryName'),
                            'BookTitle': data.get('title')
                        },
                        UpdateExpression="set NumCopies = NumCopies + :val",
                        ExpressionAttributeValues={
                            ':val': decimal.Decimal(1)
                        },
                        ReturnValues="UPDATED_NEW"
                    )
                else:
                    table.put_item(
                        Item={
                            'LibraryName': data.get('libraryName'),
                            'BookTitle': data.get('title'),
                            'NumCopies': decimal.Decimal(1)
                        }
                    )
                
                resp.message("Data added Successfully")
                return str(resp)
                
                
                except Exception as e:
                    resp.message("error in running query->" + str(e)
                    return str(resp)
   
    # LISTBOOKS request.
            elif data['request'] == "listBooks":
                try:
                    dynamodb = boto3.resource('dynamodb')
                    table = dynamodb.Table('Book')
                    pe = "BookBarcode, Title, FirstName, MiddleName, LastName, LibraryName"
                    # Expression Attribute Names for Projection Expression only.
                    
                    response = table.scan(ProjectionExpression=pe)
                    data = response['Items']
                    
                    while 'LastEvaluatedKey' in response:
                        response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
                        data.extend(response['Items'])
                    
                    resp.message(json.dumps(data))
                    return str(resp)
                    
                    
                except Exception as e:
                    resp.message("error in running query->" + str(e)
                    return str(resp)
                    
    # GETBOOK request.
            elif data['request'] == "getBook":
                dynamodb = boto3.resource('dynamodb')
                table = dynamodb.Table('Book')
                
                result = table.get_item(
                    Key={
                           'BookBarcode': event['pathParameters']['barcode']
                        }
                    )
                    
                
                resp.message(json.dumps(result['Item']))
                return str(resp)
                
    # GETBOOK request.
            elif data['request'] == "getBook": 
            try:
                if ( not data.get('barCode') ):
                    resp.message("Invalid Barcode field")
                    return str(resp)
                    
                    
                dynamodb = boto3.resource('dynamodb')
                table = dynamodb.Table('Book')
                
                try:
                    response = table.get_item(
                        Key={
                            'BookBarcode': data.get('barCode')
                        }
                    )
                    if 'Item' in response:
                        item = response['Item']
                    else:
                        item = None
                    print("\n\n response is: ", item)
                except ClientError as e:
                    item = None
                
                if( item == None ):
                    resp.message("Book doesn't exists in database!")
                    return str(resp)
                    
                
                if ( data.get('barCode')):
                    #update all fields in table
                    table.update_item(
                        Key={
                            'BookBarcode': data.get('barCode')
                            },
                            UpdateExpression='SET Title = :val2,'
                                'FirstName = :val3, MiddleName = :val4,'
                                'LastName = :val5, LibraryName = :val6',
                            ExpressionAttributeValues={
                                ':val2': data.get('title'),
                                ':val3': data.get('firstName'),
                                ':val4': data.get('middleName'),
                                ':val5': data.get('lastName'),
                                ':val6': data.get('libraryName')
                        }
                    )
                
                else:
                    resp.message("No data provided for update")
                    return str(resp)
                    
                resp.message("Data updated successfully!!")
                return str(resp)
                
            except Exception as e:
                resp.message("error in running query->" + str(e))
                return str(resp)
                
    
    # Checkout request.
            elif data['request'] == "checkout": 
                try:
                    if ( not data.get('bookBarcode') ):
                        resp.message("Invalid book barcode field!!")
                        return str(resp)
                    
                    if ( not data.get('libraryName') ):
                        resp.message("Invalid Library Name field")
                        return str(resp)
                        
                    if ( not data.get('readerBarcode') ):
                        resp.message("Invalid Reader Barcode Field")
                        return str(resp)
                        
            
                    dynamodb = boto3.resource('dynamodb')
                    
                    #Updating Transaction table with transaction details
                    table = dynamodb.Table('Transaction')
                    uid = myuuid.uuid1()
                    spot_id = str(uid)
                    
                    table.put_item(
                       Item={
                           'TransactionID': spot_id, 
                           'BookBarcode': data.get('bookBarcode'),
                           'ReaderBarcode': data.get('readerBarcode'),
                           'LibraryName': data.get('libraryName'),
                           'DateIssued': datetime.datetime.now().date().isoformat(),
                           'DateReturned': "-",
                        }
                    )
                    
                    
                    #Updating Book table with transaction details
                    table = dynamodb.Table('Book')
                    
                    try:
                        response = table.get_item(
                            Key={
                                'BookBarcode': data.get('bookBarcode')
                            }
                        )
                        if 'Item' in response:
                            item = response['Item']
                        else:
                            item = None
                        print("item is", item)
                    except ClientError as e:
                        item = None
                    
                    if( item == None ):
                        resp.message("Book doesn't exist in database!!")
                        return str(resp)
                        
                    
                    table.update_item(
                        Key={
                            'BookBarcode': data.get('bookBarcode')
                            
                                },
                                UpdateExpression='SET ReaderBarcode = :val1,'
                                    'DateIssued = :val2, DateReturned = :val3',
                                    
                                ExpressionAttributeValues={
                                    ':val1': data.get('readerBarcode'),
                                    ':val2': datetime.datetime.now().date().isoformat(),
                                    ':val3': "-"
                                    
                            }
                    )
                    
                    
                    #Updating Reader table with updating Checkout number details 
                    table = dynamodb.Table('Reader')
                    
                    try:
                        response = table.get_item(
                            Key={
                                'BarCode': data.get('readerBarcode')
                            }
                        )
                        if 'Item' in response:
                            item = response['Item']
                        else:
                            item = None
                        
                    except ClientError as e:
                        item = None
                    
                    if( item == None ):
                        resp.message("Reader doesn't exist in database")
                        return str(resp)
                        
                    table.update_item(
                        Key={
                            'BarCode': data.get('readerBarcode')
                        },
                        UpdateExpression="set Checkouts = Checkouts + :val",
                        ExpressionAttributeValues={
                                    ':val': decimal.Decimal(1)
                          },
                        ReturnValues="UPDATED_NEW"
                    )
                    
                    resp.message("Data updated successfully!!")
                    return str(resp)
                    
                except Exception as e:
                    resp.message("error in running query->" + str(e))
                    return str(resp)
                    
                    
    # Inventory request.
            elif data['request'] == "inventory": 
                if ( not data.get('libraryName') ):
                    resp.message("Invalid LibraryName field")
                    return str(resp)
                    
               
                dynamodb = boto3.resource('dynamodb')
                table = dynamodb.Table('LibraryBookDetails')
                
                    
                fe = Key('LibraryName').eq(data.get('libraryName'))
                pe = "BookTitle, NumCopies"
                        
                response = table.scan(
                    FilterExpression=fe,
                    ProjectionExpression=pe
                    )
                data = response['Items']
                
                while 'LastEvaluatedKey' in response:
                    response = table.scan(
                        ProjectionExpression=pe,
                        FilterExpression=fe,
                        ExclusiveStartKey=response['LastEvaluatedKey']
                        )
                    data.extend(response['Items'])
                
                resp.message(json.dumps(data))
                return str(resp)
                
    # Return request.
            elif data['request'] == "return": 
                try:
                    if ( not data.get('bookBarcode') ):
                        resp.message("Invalid Book Barcode field")
                        return str(resp)
                        
                    if ( not data.get('libraryName') ):
                        resp.message("Invalid LibraryName field")
                        return str(resp)
                        
                    dynamodb = boto3.resource('dynamodb')
                    
                    #Updating Transaction table with transaction details
                    table = dynamodb.Table('Transaction')
                    
                    uid = myuuid.uuid4()
                    spot_id = str(uid)
                    
                    table.put_item(
                       Item={
                           'TransactionID': spot_id, 
                           'BookBarcode': data.get('bookBarcode'),
                           'LibraryName': data.get('libraryName'),
                           'DateIssued': "-",
                           'DateReturned': datetime.datetime.now().date().isoformat()
                        }
                    )
                    
                    
                    #Updating Book table with transaction details
                    table = dynamodb.Table('Book')
                    
                    try:
                        response = table.get_item(
                            Key={
                                'BookBarcode': data.get('bookBarcode')
                            }
                        )
                        if 'Item' in response:
                            item = response['Item']
                            readerBarcode = item['ReaderBarcode']
                        else:
                            item = None
                        print("item is", item)
                        print("reader is", readerBarcode)
                    except ClientError as e:
                        item = None
                    
                    if( item == None ):
                        resp.message("Book doesn't exist in database")
                        return str(resp)
                        
                    table.update_item(
                        Key={
                            'BookBarcode': data.get('bookBarcode')
                                },
                                UpdateExpression='SET ReaderBarcode = :val1,'
                                    'DateIssued = :val2, DateReturned = :val3',
                                    
                                ExpressionAttributeValues={
                                    ':val1': "-",
                                    ':val2': "-",
                                    ':val3': "-"
                            }
                    )
                    
                    #Updating Reader table with updating Checkout number details 
                    table = dynamodb.Table('Reader')
                    
                    try:
                        response = table.get_item(
                            Key={
                                'BarCode': readerBarcode
                            }
                        )
                        if 'Item' in response:
                            item = response['Item']
                        else:
                            item = None
                        
                    except ClientError as e:
                        item = None
                    
                    if( item == None ):
                        resp.message("Reader doesn't exist in database")
                        return str(resp)
                        
                    table.update_item(
                        Key={
                            'BarCode': readerBarcode
                        },
                        UpdateExpression="set Checkouts = Checkouts - :val",
                        ExpressionAttributeValues={
                                    ':val': decimal.Decimal(1)
                          },
                        ReturnValues="UPDATED_NEW"
                    )
                    
                    resp.message("Data updated successfully")
                    return str(resp)
                    
                except Exception as e:
                    resp.message("error in running query->" + str(e))
                    return str(resp)
                    
                            
    else:
        resp.message("Error: Invalid Request")
        return str(resp)
