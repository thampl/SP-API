/*

Tomislav Hampl
tomislav.hampl@gmail.com

*/

drop procedure if exists sp_Assume_Role
go

create procedure sp_Assume_Role (
	@AccessKey varchar(max),
	@SeecretKey varchar(max)
)
as
set nocount on

/*

exec sp_Assume_Role 'XX','XXX'

*/

-- declare @AccessKey varchar(max) = 'XX'
-- declare @SeecretKey varchar(max) = 'XXX'
declare @utc datetime = GETUTCDATE()
declare @utc2 varchar(50)
select @utc2 = concat(replace(convert(varchar(10), @utc,121),'-',''),'T',replace(left(cast(@utc as time),8),':',''),'Z')

declare @string varchar(max) =concat('POST
/

content-type:application/x-www-form-urlencoded; charset=utf-8
host:sts.amazonaws.com
x-amz-date:',@utc2,'

content-type;host;x-amz-date
7d04684c051475016a30f1b67fca2e55a9c1576d876beb1037cc38480fd9a3de','') -- default

set @string = REPLACE(@string,CHAR(13)+CHAR(10),CHAR(10))
--select substring(lower(convert(varchar(4000), HASHBYTES('SHA2_256',@string),1)),3,4000) 'prvi_potpis'
declare @prvi_potpis varchar(max) = substring(lower(convert(varchar(4000), HASHBYTES('SHA2_256',@string),1)),3,4000)

declare @key varchar(max) = @SeecretKey
declare @dateStamp varchar(max) = left(@utc2,8)
declare @regionName varchar(max) = 'us-east-1' -- default
declare @serviceName varchar(max) = 'sts'

declare @signing_key varbinary(max)
declare @KeyToUse varbinary(4000), @ValueToHash varbinary(4000), @HashedValue varbinary(32);
declare @kSecret varbinary(max), @kDate varbinary(max), @kRegion varbinary(max), @kService varbinary(max), @kSigning varbinary(max)
set @kSecret = cast(concat('AWS4',@key) as varbinary(max))

SET @ValueToHash = @kSecret
SET @KeyToUse = cast(@dateStamp as varbinary(max))
SET @kDate = dbo.fn_hmac_sha256(@ValueToHash, @KeyToUse);

SET @ValueToHash = @kDate
SET @KeyToUse = cast(@regionName as varbinary(max))
SET @kRegion = dbo.fn_hmac_sha256(@ValueToHash, @KeyToUse);

SET @ValueToHash = @kRegion
SET @KeyToUse = cast(@serviceName as varbinary(max))
SET @kService = dbo.fn_hmac_sha256(@ValueToHash, @KeyToUse);

SET @ValueToHash = @kService
SET @KeyToUse = cast('aws4_request' as varbinary(max))
SET @kSigning = dbo.fn_hmac_sha256(@ValueToHash, @KeyToUse);

set @signing_key = @kSigning
-- select lower(CONVERT(varchar(8000),@signing_key,2)) signing_key

set QUOTED_IDENTIFIER on
declare @final_key varbinary(max)
select @final_key = dbo.fn_aws4_hmac('SHA2_256', @signing_key, 
CAST(
concat('AWS4-HMAC-SHA256', CHAR(10),@utc2, CHAR(10),left(@utc2,8),'/us-east-1/sts/aws4_request', CHAR(10),@prvi_potpis) as varbinary(max)));

declare @final_key2 varchar(max)
select @final_key2 = lower(CONVERT(varchar(8000),@final_key,2))


declare @xml nvarchar(max), @xml1 varchar(max)
declare @obj INT, @hr INT, @src varchar(255), @desc varchar (255), @response varchar (max), @response2 nvarchar (500), @Body as varchar(max), @Body1 as varchar(max), @startdate date, @enddtae date, @startindex int, @maxresults int
declare @srv varchar(1000)
set @srv = 'https://sts.amazonaws.com/'

declare @Authorization varchar(max)
set @Authorization = concat('AWS4-HMAC-SHA256 Credential=',@AccessKey,'/',left(@utc2,8),'/us-east-1/sts/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=',@final_key2,'')

exec sp_OAcreate 'MSXML2.ServerXMLHTTP', @obj OUT
exec sp_OAMethod @obj, 'open', NULL, 'POST', @srv, 'false'
exec sp_OAMethod @obj, 'setRequestHeader', null, 'Content-Type', 'application/x-www-form-urlencoded; charset=utf-8'
exec sp_OAMethod @obj, 'setRequestHeader', null, 'X-Amz-Date', @utc2
exec sp_OAMethod @obj, 'setRequestHeader', null, 'Authorization', @Authorization
exec sp_OAMethod @obj, 'send', null, 'Action=AssumeRole&Version=2011-06-15&RoleArn=arn:aws:iam::#####:role/RN&RoleSessionName=SQLServer'
exec sp_OAMethod @obj, 'status', @response OUTPUT
exec sp_OAMethod @obj, 'statusText', @response2 OUTPUT

print @response
print @response2

drop table if exists #tmp
create table #tmp (xxml nvarchar(max))

INSERT into #tmp (xxml)
exec sp_OAGetProperty @Obj, 'responseText' 

set @xml = null
select @xml = xxml from #tmp

print @xml

set @xml = REPLACE(@xml,' xmlns="https://sts.amazonaws.com/doc/2011-06-15/"','')

declare @hDoc as int
exec sp_xml_preparedocument @hDoc OUTPUT, @xml
	if @xml like '<Error%' begin
		select * 
		from openxml(@hDoc, '/ErrorResponse/Error',2) with(
			AccessKeyId varchar(max),
			SecretAccessKey varchar(max),
			SessionToken varchar(max),
			Message varchar(max)
		)
	end else begin
		select * , null Message
		from openxml(@hDoc, '/AssumeRoleResponse/AssumeRoleResult/Credentials',2) with(
			AccessKeyId varchar(max),
			SecretAccessKey varchar(max),
			SessionToken varchar(max)
		)
	end
exec sp_xml_removedocument @hDoc

/*
-- OK response example
<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <AssumedRoleUser>
      <AssumedRoleId>XX:SQLServer</AssumedRoleId>
      <Arn>arn:aws:sts::XX:assumed-role/XX/XX</Arn>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>XX</AccessKeyId>
      <SecretAccessKey>XX</SecretAccessKey>
      <SessionToken>XX=</SessionToken>
      <Expiration>2021-08-22T14:24:53Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
  <ResponseMetadata>
    <RequestId>77c15a3a-4e99-4321-8676-98c93c52407d</RequestId>
  </ResponseMetadata>
</AssumeRoleResponse>


-- Forbidden response example
<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>SignatureDoesNotMatch</Code>
    <Message>The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.</Message>
  </Error>
  <RequestId>617df564-1402-45b8-8066-1c7360eb6fb7</RequestId>
</ErrorResponse>

*/