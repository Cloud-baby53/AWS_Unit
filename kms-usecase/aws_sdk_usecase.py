"""
##########################################################
#     Create KMS key with alias kms_key_cse_usecase      #
##########################################################
"""
import subprocess
import sys
import os
import json
import boto3
import botocore.session
import aws_encryption_sdk

kms_client = boto3.client('kms')
account_num = boto3.client('sts').get_caller_identity().get('Account')
        
key_policy={
 "Version": "2012-10-17",
 "Id": "key-consolepolicy-3",
 "Statement": [
  {
     "Sid": "Enable IAM User Permissions",
     "Effect": "Allow",
     "Principal": {
      "AWS": "arn:aws:iam::" + account_num + ":root"
     },
     "Action": "kms:*",
     "Resource": "*"
  },
  {
     "Sid": "Allow access for Key Administrators",
     "Effect": "Allow",
     "Principal": {
      "AWS": [
         "arn:aws:iam::" + account_num + ":role/cryptobuildercloudninerole"
      ]
     },
     "Action": [
      "kms:Create*",
      "kms:Describe*",
      "kms:Enable*",
      "kms:List*",
      "kms:Put*",
      "kms:Update*",
      "kms:Revoke*",
      "kms:Disable*",
      "kms:Get*",
      "kms:Delete*",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion"
     ],
     "Resource": "*"
  },
  {
     "Sid": "Allow use of the key",
     "Effect": "Allow",
     "Principal": {
      "AWS": [
         "arn:aws:iam::" + account_num + ":role/cryptobuildercloudninerole"
      ]
     },
     "Action": [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
     ],
     "Resource": "*"
  },
  {
     "Sid": "Allow attachment of persistent resources",
     "Effect": "Allow",
     "Principal": {
      "AWS": [
         "arn:aws:iam::" + account_num + ":role/cryptobuildercloudninerole"
      ]
     },
     "Action": [
      "kms:CreateGrant",
      "kms:ListGrants",
      "kms:RevokeGrant"
     ],
     "Resource": "*",
     "Condition": {
      "Bool": {
         "kms:GrantIsForAWSResource": "true"
      }
     }
  }
 ]
}

def cycle_string(key_arn, source_plaintext, botocore_session=None):
    """Encrypts and then decrypts a string using a KMS customer master key (CMK)

    :param str key_arn: Amazon Resource Name (ARN) of the KMS CMK
    (http://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html)
    :param bytes source_plaintext: Data to encrypt
    :param botocore_session: Existing Botocore session instance
    :type botocore_session: botocore.session.Session
    """
    print('Plaintext: ', source_plaintext)
    
    # Create a KMS master key provider.
    kms_kwargs = dict(key_ids=[key_arn])
    if botocore_session is not None:
        kms_kwargs['botocore_session'] = botocore_session
    master_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(**kms_kwargs)

    # Encrypt the plaintext source data.
    ciphertext, encryptor_header = aws_encryption_sdk.encrypt(
        source=source_plaintext,
        key_provider=master_key_provider
    )
    print('Ciphertext: ', ciphertext)

    # Decrypt the ciphertext.
    cycled_plaintext, decrypted_header = aws_encryption_sdk.decrypt(
        source=ciphertext,
        key_provider=master_key_provider
    )
    print('Decrypted: ', cycled_plaintext)
    
    print(master_key_provider)
    
def cycle_file(key_arn, source_plaintext_filename, botocore_session=None):
    """Encrypts and then decrypts a string using a KMS customer master key (CMK)

    :param str key_arn: Amazon Resource Name (ARN) of the KMS CMK
    (http://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html)
    :param bytes source_plaintext: Data to encrypt
    :param botocore_session: Existing Botocore session instance
    :type botocore_session: botocore.session.Session
    """
    # Create a KMS master key provider.
    kms_kwargs = dict(key_ids=[key_arn])
    if botocore_session is not None:
        kms_kwargs['botocore_session'] = botocore_session
    master_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(**kms_kwargs)
    
    # Encrypt the plaintext source data.
    ciphertext_filename = source_plaintext_filename + '.encrypted'
    cycled_plaintext_filename = source_plaintext_filename + '.decrypted'
    
    with open(source_plaintext_filename, 'rb') as plaintext, open(ciphertext_filename, 'wb') as ciphertext:
        with aws_encryption_sdk.stream(
            mode='e',
            source=plaintext,
            key_provider=master_key_provider,
        ) as encryptor:
            for chunk in encryptor:
                ciphertext.write(chunk)
    print('Cipher file name: ', ciphertext_filename)
    
    # Decrypt the ciphertext.
    with open(ciphertext_filename, 'rb') as ciphertext, open(cycled_plaintext_filename, 'wb') as plaintext:
        with aws_encryption_sdk.stream(
            mode='d',
            source=ciphertext,
            key_provider=master_key_provider
        ) as decryptor:
            for chunk in decryptor:
                plaintext.write(chunk)
    print('Decrypt file name: ', cycled_plaintext_filename, "\n")
            
    # Verify that the "cycled" (encrypted, then decrypted) plaintext is identical to the source 
    # plaintext.
    import filecmp
    assert filecmp.cmp(source_plaintext_filename, cycled_plaintext_filename)
    
def encrypt_with_caching(key_arn, source_plaintext_filename, max_age_in_cache, cache_capacity, botocore_session=None):
    """Encrypts a string using an AWS KMS customer master key (CMK) and data key caching.
    
    :param str kms_cmk_arn: Amazon Resource Name (ARN) of the KMS customer master key
    :param float max_age_in_cache: Maximum time in seconds that a cached entry can be used
    :param int cache_capacity: Maximum number of entries to retain in cache at once
    """
    
    # Data to be encrypted
    my_data = "My plaintext data"
    # Security thresholds
    #   Max messages (or max bytes per) data key are optional
    MAX_ENTRY_MESSAGES = 100
    # Create an encryption context
    encryption_context = {"purpose": "test"}
    # Create a master key provider for the KMS customer master key (CMK)
    kms_kwargs = dict(key_ids=[key_arn])
    if botocore_session is not None:
        kms_kwargs['botocore_session'] = botocore_session
    # Create a master key provider for the KMS customer master key (CMK)
    kms_master__key_provider  = aws_encryption_sdk.KMSMasterKeyProvider(**kms_kwargs)
    # Create a local cache
    cache = aws_encryption_sdk.LocalCryptoMaterialsCache(cache_capacity)
    # Create a caching CMM
    crypto_materials_manager = aws_encryption_sdk.CachingCryptoMaterialsManager(
        master_key_provider=kms_master__key_provider,
        cache=cache,
        max_age=max_age_in_cache,
        max_messages_encrypted=MAX_ENTRY_MESSAGES,
    )
    
    # Encrypt the plaintext source data.
    ciphertext_filename = source_plaintext_filename + '.encrypted'
    cycled_plaintext_filename = source_plaintext_filename + '.decrypted'
    
    ###################################################################################################
    #   encrypt client side using a kms key and cipher text is put into sourcefile_with_caching.txt   #
    ###################################################################################################
    with open(source_plaintext_filename, 'rb') as plaintext, open(ciphertext_filename, 'wb') as ciphertext:
        with aws_encryption_sdk.stream(
            mode='e',
            source=plaintext,
            materials_manager=crypto_materials_manager,
            encryption_context=encryption_context
        ) as encryptor:
            for chunk in encryptor:
                ciphertext.write(chunk)
    print('Cipher file name: ', ciphertext_filename, "\n")
    
    ############################################################################################
    #   Decrypt the client side encrypted file sourcefile_with_caching.txt.encrypted           #
    #   The  decrypted file is called sourcefile_with_caching.txt.decrypted                    #
    ############################################################################################
    
    # Decrypt the ciphertext.
    with open(ciphertext_filename, 'rb') as ciphertext, open(cycled_plaintext_filename, 'wb') as plaintext:
        with aws_encryption_sdk.stream(
            mode='d',
            source=ciphertext,
            materials_manager=crypto_materials_manager
        ) as decryptor:
            for chunk in decryptor:
                plaintext.write(chunk)
    print('Decrypt file name: ', cycled_plaintext_filename, "\n")
            
    # Verify that the "cycled" (encrypted, then decrypted) plaintext is identical to the source 
    # plaintext.
    import filecmp
    assert filecmp.cmp(source_plaintext_filename, cycled_plaintext_filename)

def main():
    print("##########################################################")
    print("#     Create KMS key with alias kms_key_cse_usecase    #")
    print("##########################################################")

    try:
        # response = kms_client.create_key(
        #     Policy=json.dumps(key_policy),
        #     Description='Master key to encrypt objects written to S3',
        #     KeyUsage='ENCRYPT_DECRYPT',
        #     Origin='AWS_KMS',
        #     BypassPolicyLockoutSafetyCheck=False,
        #     Tags=[
        #         {
        #             'TagKey': 'crypto-aws-encryption',
        #             'TagValue': 'builder-aws-session'
        #         },
        #     ]
        # )
            
        # key_id = response['KeyMetadata']['KeyId']
        # print("key_id:", key_id)
        # # Setting a key alias
        # response = kms_client.create_alias(
        #     AliasName='alias/kms_key_cse_usecase',
        #     TargetKeyId=key_id
        # )
        
        print(" KMS Master Key with alias name kms_key_cse_usecase successfully created")
        print(" In the KMS console you should see the key with the alias kms_key_cse_usecase")
    except:
        print("Unexpected error:", sys.exc_info()[0])
        raise
    
    print("###################################")
    print("#     client side encryption      #")
    print("###################################")
    try:
        alias_name='alias/kms_key_cse_usecase'
        botocore_session = botocore.session.Session()
        #######################################################################
        #   The kmsmasterkeyprovider class is used to store the reference to  # 
        #   the customer master key                                           #
        #   https://docs.aws.amazon.com/ja_jp/encryption-sdk/latest/developer-guide/python-example-code.html#
        #######################################################################
        source_plaintext = "Hello world!"
        
        cycle_string(alias_name, source_plaintext, botocore_session)
        
        print(" Module run was successful !!")
        print(" You should see the client side encrypted file encrypted_e.txt !!")
        print(" You should see the cycled file plaintext_u_cycled.txt !!\n")
    except:
        print("Unexpected error:", sys.exc_info()[0])
        raise
    
    try:
        alias_name='alias/kms_key_cse_usecase'
        botocore_session = botocore.session.Session()
        current_directory_path = os.path.dirname(os.path.realpath(__file__)) + '/'
        source_plaintext_filename = current_directory_path + 'sourcefile.txt'
        with open(source_plaintext_filename, 'w') as plaintext:
            plaintext.write("Hello world!")
            
        cycle_file(alias_name, source_plaintext_filename, botocore_session)
        
        print(" Module run was successful !!")
        print(" You should see the client side encrypted file sourcefile.txt !!")
        print(" You should see the client side encrypted file sourcefile.txt.encrypted !!")
        print(" You should see the cycled file sourcefile.txt.decrypted !!\n")
    except:
        print("Unexpected error:", sys.exc_info()[0])
        raise
    
    print("#############################################################")
    print("#     Client side encryption with data key caching          #")
    print("#############################################################")
    try:
        """Example of encryption with data key caching."""
        alias_name='alias/kms_key_cse_usecase'
        botocore_session = botocore.session.Session()
        #############################################################
        #  Setup configuration parameters for the data key cache    #
        #############################################################
        MAX_ENTRY_AGE_SECONDS = 2.0
        CACHE_CAPACITY = 100
        current_directory_path = os.path.dirname(os.path.realpath(__file__)) + '/'
        source_plaintext_filename = current_directory_path + 'sourcefile_with_caching.txt'
        with open(source_plaintext_filename, 'w') as plaintext:
            plaintext.write("Hello world!")
        
        encrypt_with_caching(alias_name, source_plaintext_filename, MAX_ENTRY_AGE_SECONDS, CACHE_CAPACITY, botocore_session)
        
        print(" You should see the client side encrypted file sourcefile_with_caching.txt !!")
        print(" You should see the client side encrypted file sourcefile_with_caching.txt.encrypted !!")
        print(" You should see the cycled file sourcefile_with_caching.txt.decrypted !!\n")
    except:
        print("Unexpected error:", sys.exc_info()[0])
        raise
    
    
    import time
    time.sleep(5)
    print("#######################################################")
    print("#   Cleanup all data created for kms-cse-usecase      #")
    print("#######################################################")
    try:
        
        ###########################################################################
        #   Remove all the files created in the local file system                 #
        ###########################################################################
        current_directory_path = os.path.dirname(os.path.realpath(__file__)) + '/'
        plaintext_filename_path = current_directory_path + 'sourcefile.txt'
        encrypted_filename_path = current_directory_path + 'sourcefile.txt.encrypted'
        cycled_filename_path = current_directory_path + 'sourcefile.txt.decrypted'
        plaintext_with_caching_filename_path = current_directory_path + 'sourcefile_with_caching.txt'
        encrypted_with_caching_filename_path = current_directory_path + 'sourcefile_with_caching.txt.encrypted'
        cycled_with_caching_filename_path = current_directory_path + 'sourcefile_with_caching.txt.decrypted'
        
        from pathlib import Path
        if Path(plaintext_filename_path).exists():
            os.remove(plaintext_filename_path)
        if Path(encrypted_filename_path).exists():
            os.remove(encrypted_filename_path)
        if Path(cycled_filename_path).exists():
            os.remove(cycled_filename_path)
        if Path(plaintext_with_caching_filename_path).exists():
            os.remove(plaintext_with_caching_filename_path)
        if Path(encrypted_with_caching_filename_path).exists():
            os.remove(encrypted_with_caching_filename_path)
        if Path(cycled_with_caching_filename_path).exists():
            os.remove(cycled_with_caching_filename_path)
        
    #     kms_client = boto3.client('kms')
    #     response = kms_client.list_aliases(
    #         Limit=100
    #     )
    #     alias_exists = False
    #     for alias in response['Aliases']:
    #         if alias['AliasName'] == 'alias/kms_key_cse_usecase':
    #             alias_exists = True
    #     if alias_exists:
    #         response = kms_client.describe_key(
    #             KeyId='alias/kms_key_cse_usecase'
    #         )
            
    #         kms_key_id = response['KeyMetadata']['KeyId']
    #         if response['KeyMetadata']['KeyState'] != 'PendingDeletion':
    #             response = kms_client.schedule_key_deletion(
    #                 KeyId=kms_key_id,
    #                 PendingWindowInDays=7
    #             )
                
    #         # Delete the alias so that a use can run this use-case multiplt times with the same alias
    #         response_del_alias = kms_client.delete_alias(
    #             AliasName='alias/kms_key_cse_usecase'
    #         )
        print(" Cleanup Successful") 
    except:
        print("Unexpected error:", sys.exc_info()[0])
        raise

if __name__ == "__main__":

    main()