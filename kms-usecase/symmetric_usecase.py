import boto3
import os
import sys
import json
import base64
from Crypto.Cipher import AES


alias_name='alias/kms_key_cse_usecase'
kms_client = boto3.client('kms')
iv = "1234567890123456"   # 初期化ベクトル設定

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
def create_key():
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
        
def main():
    # SymmetricKeyの作成
    # delete_key('alias/symmetric_usecase')
    # key_id = create_key()['KeyMetadata']['KeyId']
    # # Setting a key alias
    # response = kms_client.create_alias(
    #     AliasName='alias/symmetric_usecase',
    #     TargetKeyId=key_id
    # )
    # print("key_id:", key_id)
    
    # Amazon KMSによる暗号化
    # 4KB以下であれば、AWS KMSによって暗号化、復元化ができる
    plaintext = "Hello world!"
    response = kms_client.encrypt(
        KeyId='alias/symmetric_usecase',
        Plaintext=plaintext.encode('utf-8')
    )
    ciphertext = response['CiphertextBlob']
    print("Plaintext: ", plaintext)
    # print("ciphertext: ", ciphertext)
    # Decrypt a data key
    response = kms_client.decrypt(
        CiphertextBlob=ciphertext
    )
    cycled_plaintext = response['Plaintext'].decode('utf-8')
    print("Plaintext Encrypt and Decript by AWS KMS")
    print("plaintext and cycled_plaintext Match: ", plaintext == cycled_plaintext)
    
    # 4KB以上のデータを暗号化するときはクライアントで暗号化してDataKeyと一緒に保管する
    # DataKeyと暗号化されたDataKeyの取得
    response = kms_client.generate_data_key(
        KeyId='alias/symmetric_usecase',
        KeySpec='AES_256'
    )
    
    plaintext_data_key = base64.b64encode(response['Plaintext'])
    encrypted_data_key = base64.b64encode(response['CiphertextBlob'])
    # print("\nplaintext_data_key", plaintext_data_key)
    # print("\nencrypted_data_key", encrypted_data_key)
    
    # 暗号化データキーの保存
    current_directory_path = os.path.dirname(os.path.realpath(__file__)) + '/'
    encrypted_data_key_file_path = current_directory_path + 'encrypted_data_key.bat'
    with open(encrypted_data_key_file_path, 'bw') as encrypted_data_key_file:
        encrypted_data_key_file.write(encrypted_data_key)
    print("DataKey Encrypted and base64.encoded  FileName saved: ", encrypted_data_key_file_path)
    
    # 暗号化
    SorcePlainText = "Hello World"
    obj = AES.new(base64.b64decode(plaintext_data_key), AES.MODE_CFB, iv)
    encryted_bytes = obj.encrypt(SorcePlainText)#パスワードの暗号化
    print("encryted_bytes: ", encryted_bytes)
    
    # 暗号化ファイルの出力    
    ciphertext_file_path = current_directory_path + 'ciphertext.bat'
    with open(ciphertext_file_path, mode='wb') as ciphertext_file:
        ciphertext_file.write(encryted_bytes)
    print("SorcePlainText Encrypted FileName saved: ", ciphertext_file_path)
    
    # 保存された暗号化データキーを取得
    with open(encrypted_data_key_file_path, 'rb') as encrypted_data_key_file:
        encrypted_data_key = encrypted_data_key_file.read()
    # 保存された暗号化ファイルの取得
    with open(ciphertext_file_path, mode='rb') as ciphertext_file:
        ciphertext = ciphertext_file.read()
    # 平文のDataKeyとMasterKey暗号化されたDataKeyをAWS KMSで複合したDataKeyを比較し、
    # DataKeyがMasterKeyで暗号化されていることを確認する
    cycled_data_key = kms_client.decrypt(
        CiphertextBlob=base64.b64decode(encrypted_data_key)
    )['Plaintext']
    print("PlaintextDataKey and CycledDataKey Match: ", base64.b64decode(plaintext_data_key) == cycled_data_key)
    
    # 複合化
    obj = AES.new(cycled_data_key, AES.MODE_CFB, iv)
    cycled_plaintext = obj.decrypt(ciphertext).decode('utf-8') #パスワードの複合化
    print("PrainText and CycledPlainText Match: ", SorcePlainText == cycled_plaintext)
    
    
if __name__ == "__main__":

    main()
    