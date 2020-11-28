import boto3
import os
import sys
import json
import os
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
def create_key(Key_Spac):
    response = "" 
    if Key_Spac == "SYMMETRIC_DEFAULT":
        response = kms_client.create_key(
            Policy=json.dumps(key_policy),
            Description='Master key to encrypt objects written to S3',
            KeyUsage='ENCRYPT_DECRYPT',
            Origin='AWS_KMS',
            BypassPolicyLockoutSafetyCheck=False,
            Tags=[
                {
                    'TagKey': 'crypto-aws-encryption',
                    'TagValue': 'builder-aws-session'
                },
            ]
        )
    else:
        response = kms_client.create_key(
            Policy=json.dumps(key_policy),
            Description='Master key to encrypt objects written to S3',
            KeyUsage='ENCRYPT_DECRYPT',
            CustomerMasterKeySpec='RSA_2048',
            Origin='AWS_KMS',
            BypassPolicyLockoutSafetyCheck=False,
            Tags=[
                {
                    'TagKey': 'crypto-aws-encryption',
                    'TagValue': 'builder-aws-session'
                },
            ]
        )
    return response
    
def delete_key(Alias_Name):
    response = kms_client.list_aliases(
        Limit=100
    )
    alias_exists = False
    for alias in response['Aliases']:
        if alias['AliasName'] == Alias_Name:
            alias_exists = True
    if alias_exists:
        response = kms_client.describe_key(
            KeyId=Alias_Name
        )
        
        kms_key_id = response['KeyMetadata']['KeyId']
        if response['KeyMetadata']['KeyState'] != 'PendingDeletion':
            response = kms_client.schedule_key_deletion(
                KeyId=kms_key_id,
                PendingWindowInDays=7
            )
            
        # Delete the alias so that a use can run this use-case multiplt times with the same alias
        response_del_alias = kms_client.delete_alias(
            AliasName=Alias_Name
        )
        print("successfully delete key")

def main():
    # delete_key('alias/asymmetric_usecase_symmetric_key')
    """
    # Asymmetric_keyのPrivate_Keyを暗号化するためのSymmetric_keyを作成する。
    response = create_key(Key_Spac = "SYMMETRIC_DEFAULT")
    Symmetric_key_id = response['KeyMetadata']['KeyId']
    response = kms_client.create_alias(
        AliasName='alias/asymmetric_usecase_symmetric_key',
        TargetKeyId=Symmetric_key_id
    )
    """
    Symmetric_key_id="9fc75673-215d-42c1-a6ed-5c6fcef8a45d"
    # Private_Keyを暗号化するためのSymmetric_keyをしてKey_pairを取得する
    response = kms_client.generate_data_key_pair(
        KeyId=Symmetric_key_id,
        KeyPairSpec='RSA_2048',
    )
    Asymmetric_key_id = response['KeyId']
    PrivateKeyCiphertextBlob=response['PrivateKeyCiphertextBlob']
    PrivateKeyPlaintext=response['PrivateKeyPlaintext']
    PublicKey=response['PublicKey']
    
    current_directory_path = os.path.dirname(os.path.realpath(__file__)) + '/'
    PrivateKeyCiphertext_file_path = current_directory_path + 'PrivateKeyCiphertext.bat'
    with open(PrivateKeyCiphertext_file_path, 'bw') as PrivateKeyCiphertext_file:
        PrivateKeyCiphertext_file.write(PrivateKeyCiphertextBlob)
        
    print("Symmetric_key_id: ", Symmetric_key_id)
    print("Asymmetric_key_id: ", Asymmetric_key_id)
    # print("\nPrivateKeyCiphertextBlob: ", PrivateKeyCiphertextBlob)
    # print("\nPrivateKeyPlaintext: ", PrivateKeyPlaintext)
    
    # 暗号化されたPrivate_keyをSymmetric_keyで復元して平文のPrivateKeyと一致することを確認する
    response = kms_client.decrypt(
        CiphertextBlob=PrivateKeyCiphertextBlob
    )
    print("Ganerated PrivateKeyPlaintext and DecryptedPrivateKeyCiphertext Match: ", response['Plaintext'] == PrivateKeyPlaintext)
    
    # KMSから取得したPair KeyをPEMに変換する
    import base64
    from Crypto.PublicKey import RSA
    
    public_key_pem = b'-----BEGIN PUBLIC KEY-----\n' + base64.b64encode(PublicKey) + b'\n-----END PUBLIC KEY-----'
    private_key_pem = b'-----BEGIN RSA PRIVATE KEY-----\n' + base64.b64encode(PrivateKeyPlaintext) + b'\n-----END RSA PRIVATE KEY-----'
    
    # Keyの保存
    current_directory_path = os.path.dirname(os.path.realpath(__file__)) + '/'
    KeyPair_Public_key_file_path = current_directory_path + 'PublicKey.pem'
    KeyPair_Private_key_file_path = current_directory_path + 'PrivateKey.pem'
    with open(KeyPair_Public_key_file_path, 'wb') as KeyPair_Public_key_file, open(KeyPair_Private_key_file_path, 'wb') as KeyPair_Private_key_file:
        KeyPair_Public_key_file.write(public_key_pem)
        KeyPair_Private_key_file.write(private_key_pem)

    with open(KeyPair_Public_key_file_path, 'rb') as KeyPair_Public_key_file, open(KeyPair_Private_key_file_path, 'rb') as KeyPair_Private_key_file:
        public_key = RSA.importKey(KeyPair_Public_key_file.read())
        private_key = RSA.importKey(KeyPair_Private_key_file.read())
    
    # print("public_key: ", public_key.exportKey('PEM'))
    # print("private_key: ", private_key.exportKey('PEM'))
    
    # 準備したKey Pairを利用した暗号化と複合
    from Crypto.Cipher import PKCS1_OAEP
    
    Plaintext = "Hello Python World!"
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    
    cipher_rsa = PKCS1_OAEP.new(public_key)
    ciphertext = cipher_rsa.encrypt(Plaintext.encode())
    print("Plaintext: ", Plaintext)
    # print("ciphertext: ", ciphertext)
    decipher_rsa = PKCS1_OAEP.new(private_key)
    cycled_plaintext = decipher_rsa.decrypt(ciphertext)
    # print("cycled_plaintext: ", cycled_plaintext.decode())
    print("Plaintext and Cycled_plaintext Match: ", Plaintext == cycled_plaintext.decode())
    
    # delete_key('alias/asymmetric_usecase_symmetric_key')
    from pathlib import Path
    if Path(KeyPair_Public_key_file_path).exists():
        os.remove(KeyPair_Public_key_file_path)
    if Path(KeyPair_Private_key_file_path).exists():
        os.remove(KeyPair_Private_key_file_path)

    #ちなみにAWS KMSを利用せずにKey Pairを作成し、暗号化、複合化する
    """
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
     
    Plaintext = "Hello Python World!"
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    
    cipher_rsa = PKCS1_OAEP.new(public_key)
    ciphertext = cipher_rsa.encrypt(Plaintext.encode())
    print("Plaintext: ", Plaintext)
    # print("ciphertext: ", ciphertext)
    
    decipher_rsa = PKCS1_OAEP.new(private_key)
    cycled_plaintext = decipher_rsa.decrypt(ciphertext)
    print("cycled_plaintext: ",cycled_plaintext.decode())
    print("Plaintext and Cycled_plaintext Match: ", Plaintext == cycled_plaintext.decode())
    """
if __name__ == "__main__":

    main()