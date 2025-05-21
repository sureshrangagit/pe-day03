package s3.security

deny[msg] {
  input.PublicAccessBlockConfiguration.BlockPublicAcls == false
  msg := "Public ACLs must be blocked"
}

deny[msg] {
  input.EncryptionConfiguration.Rules[_].ApplyServerSideEncryptionByDefault.SSEAlgorithm != "AES256"
  msg := "S3 bucket must use AES256 encryption"
}

