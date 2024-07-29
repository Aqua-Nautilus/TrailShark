json = require("json")

-- Define the CloudTrail protocol
local p_cloudtrail = Proto("cloudtrail", "AWS CloudTrail")

-- Define the protocol fields including nested fields
local field_defs = {
	requestParameters_formatted = "requestParameters_formatted",
	responseElements_formatted = "responseElements_formatted",
	info = "info",
	link = "link",
	errorCode = "errorCode",
	errorMessage = "errorMessage",
	madeByRecorder = "madeByRecorder",
	derivativeEvent = "derivativeEvent",
    eventVersion = "eventVersion",
    eventTime = "eventTime",
    eventSource = "destination",
    eventName = "eventName",
    awsRegion = "awsRegion",
    sourceIPAddress = "source",
    userAgent = "userAgent",
    requestID = "requestID",
    eventID = "eventID",
    readOnly = "readOnly",
    eventType = "eventType",
    managementEvent = "managementEvent",
    recipientAccountId = "recipientAccountId",
    eventCategory = "eventCategory",
    userIdentity = "userIdentity",
	["userIdentity.arn"] = "arn",
	["userIdentity.name"] = "name",
    ["userIdentity.type"] = "type",
    ["userIdentity.principalId"] = "principalId",
    ["userIdentity.accountId"] = "accountId",
    ["userIdentity.accessKeyId"] = "accessKeyId",
	["userIdentity.sessionContext"] = "sessionContext", 
	["userIdentity.sessionContext.sessionIssuer"] = "sessionIssuer",
    ["userIdentity.sessionContext.sessionIssuer.type"] = "type",
    ["userIdentity.sessionContext.sessionIssuer.principalId"] = "principalId",
    ["userIdentity.sessionContext.sessionIssuer.arn"] = "arn",
    ["userIdentity.sessionContext.sessionIssuer.accountId"] = "accountId",
    ["userIdentity.sessionContext.sessionIssuer.userName"] = "userName",
	["userIdentity.sessionContext.attributes"] = "attributes",
    ["userIdentity.sessionContext.attributes.creationDate"] = "creationDate",
    ["userIdentity.sessionContext.attributes.mfaAuthenticated"] = "mfaAuthenticated",
    ["userIdentity.invokedBy"] = "invokedBy",
    ["userIdentity.userName"] = "userName",
	requestParameters = "requestParameters",
	["requestParameters.maxResults"] = "maxResults",
	["requestParameters.includeAllInstances"] = "includeAllInstances",
	["requestParameters"] = "requestParameters",
	["requestParameters.template"] = "template",
	["requestParameters.maxRecords"] = "maxRecords",
	["requestParameters.includeShared"] = "includeShared",
	["requestParameters.startTime"] = "startTime",
	["requestParameters.endTime"] = "endTime",
	["requestParameters.roleArn"] = "roleArn",
	["requestParameters.roleSessionName"] = "roleSessionName",
	["requestParameters.durationSeconds"] = "durationSeconds",
	["requestParameters.externalId"] = "externalId",
	["requestParameters.encryptionAlgorithm"] = "encryptionAlgorithm",
	["requestParameters.paginationToken"] = "paginationToken",
	["requestParameters.resourcesPerPage"] = "resourcesPerPage",
	["requestParameters.resourceTypeFilters"] = "resourceTypeFilters",
	["requestParameters.startDate"] = "startDate",
	["requestParameters.endDate"] = "endDate",
	["requestParameters.masterRegion"] = "masterRegion",
	["requestParameters.functionVersion"] = "functionVersion",
	["requestParameters.maxItems"] = "maxItems",
	["requestParameters.instanceId"] = "instanceId",
	["requestParameters.stateMachineArn"] = "stateMachineArn",
	["requestParameters.minimumStartTime"] = "minimumStartTime",
	["requestParameters.tableName"] = "tableName",
	["requestParameters.bucketName"] = "bucketName",
	["requestParameters.Host"] = "Host",
	["requestParameters.x-amz-acl"] = "x-amz-acl",
	["requestParameters.x-amz-server-side-encryption"] = "x-amz-server-side-encryption",
	["requestParameters.key"] = "key",
	["requestParameters.instanceProfileName"] = "instanceProfileName",
	["requestParameters.x-id"] = "x-id",
	["requestParameters.tagging"] = "tagging",
	["requestParameters.autoScalingGroupNames"] = "autoScalingGroupNames",
	["requestParameters.pageSize"] = "pageSize",
	["requestParameters.agentVersion"] = "agentVersion",
	["requestParameters.agentStatus"] = "agentStatus",
	["requestParameters.platformType"] = "platformType",
	["requestParameters.platformName"] = "platformName",
	["requestParameters.platformVersion"] = "platformVersion",
	["requestParameters.iPAddress"] = "iPAddress",
	["requestParameters.computerName"] = "computerName",
	["requestParameters.agentName"] = "agentName",
	["requestParameters.availabilityZone"] = "availabilityZone",
	["requestParameters.availabilityZoneId"] = "availabilityZoneId",
	["requestParameters.sSMConnectionChannel"] = "sSMConnectionChannel",
	["requestParameters.loadBalancerArn"] = "loadBalancerArn",
	["requestParameters.listenerArn"] = "listenerArn",
	["requestParameters.lookupAttributes"] = "lookupAttributes",
	["requestParameters.partNumber"] = "partNumber",
	["requestParameters.uploadId"] = "uploadId",
	["requestParameters.encoding-type"] = "encoding-type",
	["requestParameters.prefix"] = "prefix",
	["requestParameters.uploads"] = "uploads",
	["requestParameters.roleName"] = "roleName",
	["requestParameters.targetGroupArn"] = "targetGroupArn",
	["requestParameters.location"] = "location",
	["requestParameters.includePublic"] = "includePublic",
	["requestParameters.sAMLAssertionID"] = "sAMLAssertionID",
	["requestParameters.principalArn"] = "principalArn",
	["requestParameters.aggregateField"] = "aggregateField",
	["requestParameters.name"] = "name",
	["requestParameters.input"] = "input",
	["requestParameters.logGroupName"] = "logGroupName",
	["requestParameters.logStreamName"] = "logStreamName",
	["requestParameters.unmask"] = "unmask",
	["requestParameters.limit"] = "limit",
	["requestParameters.allRegions"] = "allRegions",
	["requestParameters.Type"] = "Type",
	["requestParameters.eventCategory"] = "eventCategory",
	["requestParameters.resourceIdList"] = "resourceIdList",
	["requestParameters.trailName"] = "trailName",
	["requestParameters.secretId"] = "secretId",
	["requestParameters.dBInstanceIdentifier"] = "dBInstanceIdentifier",
	["requestParameters.marker"] = "marker",
	["requestParameters.acl"] = "acl",
	["requestParameters.resourceArns"] = "resourceArns",
	["requestParameters.cluster"] = "cluster",
	["requestParameters.dBSnapshotIdentifier"] = "dBSnapshotIdentifier",
	["requestParameters.numberOfBytes"] = "numberOfBytes",
	["requestParameters.keyId"] = "keyId",
	["requestParameters.resourceName"] = "resourceName",
	["requestParameters.policy"] = "policy",
	["requestParameters.showCacheNodeInfo"] = "showCacheNodeInfo",
	["requestParameters.stackStatusFilter"] = "stackStatusFilter",
	["requestParameters.list-type"] = "list-type",
	["requestParameters.max-keys"] = "max-keys",
	["requestParameters.filters"] = "filters",
	["requestParameters.queryExecutionId"] = "queryExecutionId",
	["requestParameters.queryString"] = "queryString",
	["requestParameters.clientRequestToken"] = "clientRequestToken",
	["requestParameters.nextToken"] = "nextToken",
	["requestParameters.streamName"] = "streamName",
	["requestParameters.checkId"] = "checkId",
	["requestParameters.type"] = "type",
	["requestParameters.fileSystemId"] = "fileSystemId",
	["requestParameters.forAccount"] = "forAccount",
	["requestParameters.catalogId"] = "catalogId",
	["requestParameters.entries"] = "entries",
	["requestParameters.supportedPermissionTypes"] = "supportedPermissionTypes",
	["requestParameters.returnBaseTablesForViews"] = "returnBaseTablesForViews",
	["requestParameters.X-Amz-Date"] = "X-Amz-Date",
	["requestParameters.X-Amz-Algorithm"] = "X-Amz-Algorithm",
	["requestParameters.X-Amz-SignedHeaders"] = "X-Amz-SignedHeaders",
	["requestParameters.X-Amz-Content-Sha256"] = "X-Amz-Content-Sha256",
	["requestParameters.X-Amz-Expires"] = "X-Amz-Expires",
	["requestParameters.fetch-owner"] = "fetch-owner",
	["requestParameters.resource"] = "resource",
	["requestParameters.lifecycle"] = "lifecycle",
	["requestParameters.clusters"] = "clusters",
	["requestParameters.include"] = "include",
	["requestParameters.addonName"] = "addonName",
	["requestParameters.stackName"] = "stackName",
	["requestParameters.restApiId"] = "restApiId",
	["requestParameters.cors"] = "cors",
	["requestParameters.logging"] = "logging",
	["requestParameters.notification"] = "notification",
	["requestParameters.versioning"] = "versioning",
	["requestParameters.website"] = "website",
	["requestParameters.requestPayment"] = "requestPayment",
	["requestParameters.accelerate"] = "accelerate",
	["requestParameters.encryption"] = "encryption",
	["requestParameters.replication"] = "replication",
	["requestParameters.publicAccessBlock"] = "publicAccessBlock",
	["requestParameters.object-lock"] = "object-lock",
	["requestParameters.streamARN"] = "streamARN",
	["requestParameters.keySpec"] = "keySpec",
	["requestParameters.functionName"] = "functionName",
	["requestParameters.language"] = "language",
	["requestParameters.GroupName"] = "GroupName",
	["requestParameters.Filters"] = "Filters",
	["requestParameters.tagFilters"] = "tagFilters",
	["requestParameters.origin"] = "origin",
	["requestParameters.dryRun"] = "dryRun",
	["requestParameters.utterance"] = "utterance",
	["requestParameters.conversationId"] = "conversationId",
	["requestParameters.workGroup"] = "workGroup",
	["requestParameters.includePreviewFeatures"] = "includePreviewFeatures",
	["requestParameters.includeDeprecatedFeaturesAccess"] = "includeDeprecatedFeaturesAccess",
	["requestParameters.includeDeprecatedRuntimeDetails"] = "includeDeprecatedRuntimeDetails",
	["requestParameters.includeUnreservedConcurrentExecutionsMinimum"] = "includeUnreservedConcurrentExecutionsMinimum",
	["requestParameters.includeBlacklistedFeatures"] = "includeBlacklistedFeatures",
	["requestParameters.qualifier"] = "qualifier",	
	responseElements = "responseElements",
	["responseElements.x-amz-server-side-encryption"] = "x-amz-server-side-encryption",
	["responseElements.x-amz-expiration"] = "x-amz-expiration",
	["responseElements.x-amz-version-id"] = "x-amz-version-id",
	["responseElements.subject"] = "subject",
	["responseElements.subjectType"] = "subjectType",
	["responseElements.issuer"] = "issuer",
	["responseElements.audience"] = "audience",
	["responseElements.nameQualifier"] = "nameQualifier",
	["responseElements.executionArn"] = "executionArn",
	["responseElements.startDate"] = "startDate",
	["responseElements.packedPolicySize"] = "packedPolicySize",
	["responseElements.queryExecutionId"] = "queryExecutionId",
	["responseElements.requestId"] = "requestId",
	["responseElements.keyId"] = "keyId",
	["responseElements.subjectFromWebIdentityToken"] = "subjectFromWebIdentityToken",
	["responseElements.provider"] = "provider",
	["responseElements.credentials"] = "credentials",
	["responseElements.credentials.accessKeyId"] = "accessKeyId",
	["responseElements.credentials.sessionToken"] = "sessionToken",
	["responseElements.credentials.expiration"] = "expiration",
	["responseElements.assumedRoleUser"] = "assumedRoleUser",
	["responseElements.assumedRoleUser.assumedRoleId"] = "assumedRoleId",
	["responseElements.assumedRoleUser.arn"] = "arn",
	additionalEventData = "additionalEventData",
	["additionalEventData.grantId"] = "grantId",
	["additionalEventData.SignatureVersion"] = "SignatureVersion",
	["additionalEventData.CipherSuite"] = "CipherSuite",
	["additionalEventData.bytesTransferredIn"] = "bytesTransferredIn",
	["additionalEventData.SSEApplied"] = "SSEApplied",
	["additionalEventData.AuthenticationMethod"] = "AuthenticationMethod",
	["additionalEventData.x-amz-id-2"] = "x-amz-id-2",
	["additionalEventData.bytesTransferredOut"] = "bytesTransferredOut"
}



-- Initialize ProtoFields dynamically from field definitions
local fields = {}
for key, label in pairs(field_defs) do
    fields[key] = ProtoField.string('cloudtrail.' .. key, label)
end
p_cloudtrail.fields = fields

-- Function to recursively add fields to the subtree
local function addFieldsToSubtree(subtree, data, prefix)
    prefix = prefix or ""
    for key, value in pairs(data) do
        local field_key = prefix .. key
        local protoField = fields[field_key]
        if protoField then
            if type(value) == "table" then
                -- Create a subtree for nested JSON objects
                local nestedSubtree = subtree:add(protoField, key)
                addFieldsToSubtree(nestedSubtree, value, field_key .. ".")
            else
                -- Add the actual data as a field in the subtree
                subtree:add(protoField, tostring(value))
            end
        end
    end
end

-- Function to add the specific information only when eventID is not null
local function addInformation(subtree, data)
    local region = data.awsRegion or "unknown-region"
    local eventid = data.eventID
    if eventid then  -- Check if eventid is not nil or empty
        local url = string.format("https://%s.console.aws.amazon.com/cloudtrailv2/home?region=%s#/events/%s", region, region, eventid)
        subtree:add(fields.link, url)
    end
end


function format_nested_object(obj)
    if type(obj) == "table" then
        local parts = {}
        for k, v in pairs(obj) do
            parts[#parts + 1] = string.format('"%s":%s', k, format_nested_object(v))
        end
        return "{" .. table.concat(parts, ",") .. "}"
    else
        -- Handle strings by adding quotes and escaping internal quotes
        if type(obj) == "string" then
            return string.format('"%s"', obj:gsub('"', '\\"'))
        else
            return tostring(obj)
        end
    end
end


function add_formatted_json(subtree, data)
    subtree:add(fields.requestParameters_formatted, format_nested_object(data.requestParameters))
	subtree:add(fields.responseElements_formatted, format_nested_object(data.responseElements))

end
-- Dissector function to parse the packet data
function p_cloudtrail.dissector(buf, pinfo, tree)
    local subtree = tree:add(p_cloudtrail, buf(0, -1))
    local status, data = pcall(json.decode, buf:bytes():raw())
    
    if status then
        addFieldsToSubtree(subtree, data)
		addInformation(subtree, data)
		add_formatted_json(subtree, data)
    else
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Error decoding JSON: " .. data)
    end
end

-- Register the dissector to a specific encapsulation type
local wtap_encap_table = DissectorTable.get("wtap_encap")
wtap_encap_table:add(wtap.USER1, p_cloudtrail)
