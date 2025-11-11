const crypto = require("./crypto");

const ALIDNS_HOST = 'alidns.aliyuncs.com';
const HTTP_METHOD = "GET";

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function getCombinedParams(reqParams, commonParams) {
    const combinedParams = {};
    Object.keys(reqParams).forEach((x) => {
        combinedParams[x] = reqParams[x];
    });
    Object.keys(commonParams).forEach((x) => {
        combinedParams[x] = commonParams[x];
    });
    const timestamp = new Date();
    combinedParams["Timestamp"] = timestamp.toISOString();
    combinedParams["SignatureNonce"] = getRandomInt(100000000, 1000000000 - 1);
    return combinedParams;
}

function convertJsonToQueryString(params) {
    return Object.keys(params)
        .sort()
        .map(x => encodeURIComponent(x) + "=" + encodeURIComponent(params[x]))
        .join("&");
}

function getStringToSign(canonicalizedQueryString) {
    return HTTP_METHOD + '&' + encodeURIComponent('/') + '&' + encodeURIComponent(canonicalizedQueryString);
}

function getQueryString(accessKeySecret, reqParams, commonParams) {
    const combinedParams = getCombinedParams(reqParams, commonParams);
    let canonicalizedQueryString = convertJsonToQueryString(combinedParams);
    const stringToSign = getStringToSign(canonicalizedQueryString);
    const hmac = crypto.HmacSHA1(stringToSign, accessKeySecret + '&');
    const Signature = crypto.enc.Base64.stringify(hmac);
    canonicalizedQueryString += '&Signature=' + encodeURIComponent(Signature);
    return canonicalizedQueryString;
}

function getPath(accessKeySecret, reqParams, commonParams) {
    return '/?' + getQueryString(accessKeySecret, reqParams, commonParams);
}

export async function add_challenge(provider, domain, challenge_key) {
    const accessKeyId = provider["accessKeyId"];
    const accessKeySecret = provider["accessKeySecret"];
    const subDomain = domain;
    const domainName = subDomain.split('.').slice(-2).join('.');
    const rr = subDomain.split('.').slice(0, -2).join('.');
    const describeSubParams = {
        Action: 'DescribeSubDomainRecords',
        SubDomain: subDomain
    };
    const updateParmas = {
        Action: 'UpdateDomainRecord',
        RecordId: '',
        RR: rr,
        Type: 'TXT',
        Value: challenge_key
    };
    const addParmas = {
        Action: 'AddDomainRecord',
        DomainName: domainName,
        RR: rr,
        Type: 'TXT',
        Value: challenge_key
    };

    const commonParams = {
        Format: 'JSON',
        Version: '2015-01-09',
        AccessKeyId: accessKeyId,
        SignatureMethod: 'HMAC-SHA1',
        SignatureVersion: '1.0'
    };

    try {
        // 首先获取域名信息, 目的是获取要更新的域名的 RecordId
        const url = `http://${ALIDNS_HOST}${getPath(accessKeySecret, describeSubParams, commonParams)}`;

        let res = await fetch(url);
        if (res.status !== 200) {
            return false;
        }
        let body = await res.text();
        const result = JSON.parse(body);
        console.log(result);

        // 获取要更新的域名的 RecordId, 并检查是否需要更新
        let shouldUpdate = false;
        let shouldAdd = true;
        result.DomainRecords.Record
            .filter(record => record.RR === updateParmas.RR && record.Type === updateParmas.Type)
            .forEach(record => {
                shouldAdd = false;
                if (record.Value !== updateParmas.Value) {
                    shouldUpdate = true;
                    updateParmas.RecordId = record.RecordId;
                }
            });
        if (shouldUpdate) {
            // 更新域名的解析
            const updateUrl = `http://${ALIDNS_HOST}${getPath(accessKeySecret, updateParmas, commonParams)}`;
            let res = await fetch(updateUrl);
            return res.status === 200;
        } else if (shouldAdd) {
            // 增加新的域名解析
            const addUrl = `http://${ALIDNS_HOST}${getPath(accessKeySecret, addParmas, commonParams)}`;
            let res = await fetch(addUrl);
            return res.status === 200;
        }
    } catch (e) {
        return false;
    }
    return true;
}

export async function del_challenge(provider, domain, challenge_key) {
    const accessKeyId = provider["accessKeyId"];
    const accessKeySecret = provider["accessKeySecret"];
    const subDomain = domain;
    const rr = subDomain.split('.').slice(0, -2).join('.');
    const describeSubParams = {
        Action: 'DescribeSubDomainRecords',
        SubDomain: subDomain
    };
    const deleteParmas = {
        Action: 'DeleteDomainRecord',
        RecordId: '',
    };

    const commonParams = {
        Format: 'JSON',
        Version: '2015-01-09',
        AccessKeyId: accessKeyId,
        SignatureMethod: 'HMAC-SHA1',
        SignatureVersion: '1.0'
    };

    try {
        // 首先获取域名信息, 目的是获取要更新的域名的 RecordId
        const url = `http://${ALIDNS_HOST}${getPath(accessKeySecret, describeSubParams, commonParams)}`;
        let res = await fetch(url);
        if (res.status !== 200) {
            return false;
        }
        let body = await res.text();
        const result = JSON.parse(body);

        let shouldDelete = false;
        result.DomainRecords.Record
            .filter(record => record.RR === rr && record.Type === 'TXT')
            .forEach(record => {
                deleteParmas.RecordId = record.RecordId;
                shouldDelete = true;
            });
        if (shouldDelete) {
            // 增加新的域名解析
            const addUrl = `http://${ALIDNS_HOST}${getPath(accessKeySecret, deleteParmas, commonParams)}`;
            let res = await fetch(addUrl);
            return res.status === 200;
        }
    } catch (e) {
        return false;
    }
    return true;
}

