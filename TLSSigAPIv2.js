var crypto = require('crypto');
var zlib = require('zlib');

var base64url = {};

var newBuffer = function (fill, encoding) {
    return Buffer.from ? Buffer.from(fill, encoding) : new Buffer(fill, encoding)
};

base64url.unescape = function unescape(str) {
    return (str + Array(5 - str.length % 4))
        .replace(/_/g, '=')
        .replace(/\-/g, '/')
        .replace(/\*/g, '+');
};

base64url.escape = function escape(str) {
    return str.replace(/\+/g, '*')
        .replace(/\//g, '-')
        .replace(/=/g, '_');
};

base64url.encode = function encode(str) {
    return this.escape(newBuffer(str).toString('base64'));
};

base64url.decode = function decode(str) {
    return newBuffer(this.unescape(str), 'base64').toString();
};

function base64encode(str) {
    return newBuffer(str).toString('base64')
}

function base64decode(str) {
    return newBuffer(str, 'base64').toString()
}

var Api = function (sdkappid, key) {
    this.sdkappid = sdkappid;
    this.key = key;
};
/**
 * Generate the hmac value of base64 by passing in the parameters
 * @param identifier
 * @param currTime
 * @param expire
 * @returns {string}
 * @private
 */
Api.prototype._hmacsha256 = function (identifier, currTime, expire, base64UserBuf) {
    var contentToBeSigned = "TLS.identifier:" + identifier + "\n";
    contentToBeSigned += "TLS.sdkappid:" + this.sdkappid + "\n";
    contentToBeSigned += "TLS.time:" + currTime + "\n";
    contentToBeSigned += "TLS.expire:" + expire + "\n";
    if (null != base64UserBuf) {
        contentToBeSigned += "TLS.userbuf:" + base64UserBuf + "\n";
    }
    const hmac = crypto.createHmac("sha256", this.key);
    return hmac.update(contentToBeSigned).digest('base64');
};

/**
 * User-defined userbuf is used for the encrypted string of TRTC service entry permission
 * @brief generate userbuf
 * @param account username
 * @param dwSdkappid sdkappid
 * @param dwAuthID  digital room number
 * @param dwExpTime Expiration time: The expiration time of the encrypted string of this permission. Expiration time = now+dwExpTime
 * @param dwPrivilegeMap User permissions, 255 means all permissions
 * @param dwAccountType User type, default is 0
 * @param roomStr String room number
 * @return userbuf string  returned userbuf
 */

Api.prototype._genUserbuf = function (account, dwAuthID, dwExpTime,
    dwPrivilegeMap, dwAccountType, roomstr) {

    let accountLength = account.length;
    let roomstrlength = 0;
    let length = 1 + 2 + accountLength + 20 ;
    if (null != roomstr)
    {
        roomstrlength = roomstr.length;
        length = length + 2 + roomstrlength;
    }
    let offset = 0;
    let userBuf = new Buffer.alloc(length);

    //cVer
    if (null != roomstr)
        userBuf[offset++] = 1;
    else
        userBuf[offset++] = 0;

    //wAccountLen
    userBuf[offset++] = (accountLength & 0xFF00) >> 8;
    userBuf[offset++] = accountLength & 0x00FF;

    //buffAccount
    for (; offset < 3 + accountLength; ++offset) {
        userBuf[offset] = account.charCodeAt(offset - 3);
    }

    //dwSdkAppid
    userBuf[offset++] = (this.sdkappid & 0xFF000000) >> 24;
    userBuf[offset++] = (this.sdkappid & 0x00FF0000) >> 16;
    userBuf[offset++] = (this.sdkappid & 0x0000FF00) >> 8;
    userBuf[offset++] = this.sdkappid & 0x000000FF;

    //dwAuthId
    userBuf[offset++] = (dwAuthID & 0xFF000000) >> 24;
    userBuf[offset++] = (dwAuthID & 0x00FF0000) >> 16;
    userBuf[offset++] = (dwAuthID & 0x0000FF00) >> 8;
    userBuf[offset++] = dwAuthID & 0x000000FF;

    //过期时间：dwExpTime+now
    let expire = Date.now() / 1000 + dwExpTime;
    userBuf[offset++] = (expire & 0xFF000000) >> 24;
    userBuf[offset++] = (expire & 0x00FF0000) >> 16;
    userBuf[offset++] = (expire & 0x0000FF00) >> 8;
    userBuf[offset++] = expire & 0x000000FF;

    //dwPrivilegeMap
    userBuf[offset++] = (dwPrivilegeMap & 0xFF000000) >> 24;
    userBuf[offset++] = (dwPrivilegeMap & 0x00FF0000) >> 16;
    userBuf[offset++] = (dwPrivilegeMap & 0x0000FF00) >> 8;
    userBuf[offset++] = dwPrivilegeMap & 0x000000FF;

    //dwAccountType
    userBuf[offset++] = (dwAccountType & 0xFF000000) >> 24;
    userBuf[offset++] = (dwAccountType & 0x00FF0000) >> 16;
    userBuf[offset++] = (dwAccountType & 0x0000FF00) >> 8;
    userBuf[offset++] = dwAccountType & 0x000000FF;

    if (null != roomstr) {
        //roomstrlength
        userBuf[offset++] = (roomstr.length & 0xFF00) >> 8;
        userBuf[offset++] = roomstr.length & 0x00FF;

        //roomstr
        for (; offset < length; ++offset) {
            userBuf[offset] = roomstr.charCodeAt(offset - (length - roomstr.length));
        }
    }

    return userBuf;
}
Api.prototype.genSig = function (userid, expire, userBuf) {
    var currTime = Math.floor(Date.now() / 1000);

    var sigDoc = {
        'TLS.ver': "2.0",
        'TLS.identifier': "" + userid,
        'TLS.sdkappid': Number(this.sdkappid),
        'TLS.time': Number(currTime),
        'TLS.expire': Number(expire)
    };

    var sig = '';
    if (null != userBuf) {
        var base64UserBuf = base64encode(userBuf);
        sigDoc['TLS.userbuf'] = base64UserBuf;
        sig = this._hmacsha256(userid, currTime, expire, base64UserBuf);
    } else {
        sig = this._hmacsha256(userid, currTime, expire, null);
    }
    sigDoc['TLS.sig'] = sig;

    var compressed = zlib.deflateSync(newBuffer(JSON.stringify(sigDoc))).toString('base64');
    return base64url.escape(compressed);
}

/**
 * Function: Used to issue UserSig that is required by the TRTC and CHAT services.
 *
 * Parameter description:
 * @param userid - User ID. The value can be up to 32 bytes in length and contain letters (a-z and A-Z), digits (0-9), underscores (_), and hyphens (-).
 * @param expire - UserSig expiration time, in seconds. For example, 86400 indicates that the generated UserSig will expire one day after being generated.
*/
Api.prototype.genUserSig = function (userid, expire) {
    return this.genSig(userid, expire, null);
};

/**
 * Function:
 * Used to issue PrivateMapKey that is optional for room entry.
 * PrivateMapKey must be used together with UserSig but with more powerful permission control capabilities.
 *  - UserSig can only control whether a UserID has permission to use the TRTC service. As long as the UserSig is correct, the user with the corresponding UserID can enter or leave any room.
 *  - PrivateMapKey specifies more stringent permissions for a UserID, including whether the UserID can be used to enter a specific room and perform audio/video upstreaming in the room.
 * To enable stringent PrivateMapKey permission bit verification, you need to enable permission key in TRTC console > Application Management > Application Info.
 *
 * Parameter description:
 * userid - User ID. The value can be up to 32 bytes in length and contain letters (a-z and A-Z), digits (0-9), underscores (_), and hyphens (-).
 * roomid - ID of the room to which the specified UserID can enter.
 * expire - PrivateMapKey expiration time, in seconds. For example, 86400 indicates that the generated PrivateMapKey will expire one day after being generated.
 * privilegeMap - Permission bits. Eight bits in the same byte are used as the permission switches of eight specific features:
 *  - Bit 1: 0000 0001 = 1, permission for room creation
 *  - Bit 2: 0000 0010 = 2, permission for room entry
 *  - Bit 3: 0000 0100 = 4, permission for audio sending
 *  - Bit 4: 0000 1000 = 8, permission for audio receiving
 *  - Bit 5: 0001 0000 = 16, permission for video sending
 *  - Bit 6: 0010 0000 = 32, permission for video receiving
 *  - Bit 7: 0100 0000 = 64, permission for substream video sending (screen sharing)
 *  - Bit 8: 1000 0000 = 200, permission for substream video receiving (screen sharing)
 *  - privilegeMap == 1111 1111 == 255: Indicates that the UserID has all feature permissions of the room specified by roomid.
 *  - privilegeMap == 0010 1010 == 42: Indicates that the UserID has only the permissions to enter the room and receive audio/video data.
 */

Api.prototype.genPrivateMapKey = function (userid, expire, roomid, privilegeMap) {
    var userBuf = this._genUserbuf(userid, roomid, expire, privilegeMap, 0, null);
    return this.genSig(userid, expire, userBuf);

};

/**
 * Function:
 * Used to issue PrivateMapKey that is optional for room entry.
 * PrivateMapKey must be used together with UserSig but with more powerful permission control capabilities.
 *  - UserSig can only control whether a UserID has permission to use the TRTC service. As long as the UserSig is correct, the user with the corresponding UserID can enter or leave any room.
 *  - PrivateMapKey specifies more stringent permissions for a UserID, including whether the UserID can be used to enter a specific room and perform audio/video upstreaming in the room.
 * To enable stringent PrivateMapKey permission bit verification, you need to enable permission key in TRTC console > Application Management > Application Info.
 *
 * Parameter description:
 * @param userid - User ID. The value can be up to 32 bytes in length and contain letters (a-z and A-Z), digits (0-9), underscores (_), and hyphens (-).
 * @param roomstr - ID of the room to which the specified UserID can enter.
 * @param expire - PrivateMapKey expiration time, in seconds. For example, 86400 indicates that the generated PrivateMapKey will expire one day after being generated.
 * @param privilegeMap - Permission bits. Eight bits in the same byte are used as the permission switches of eight specific features:
 *  - Bit 1: 0000 0001 = 1, permission for room creation
 *  - Bit 2: 0000 0010 = 2, permission for room entry
 *  - Bit 3: 0000 0100 = 4, permission for audio sending
 *  - Bit 4: 0000 1000 = 8, permission for audio receiving
 *  - Bit 5: 0001 0000 = 16, permission for video sending
 *  - Bit 6: 0010 0000 = 32, permission for video receiving
 *  - Bit 7: 0100 0000 = 64, permission for substream video sending (screen sharing)
 *  - Bit 8: 1000 0000 = 200, permission for substream video receiving (screen sharing)
 *  - privilegeMap == 1111 1111 == 255: Indicates that the UserID has all feature permissions of the room specified by roomid.
 *  - privilegeMap == 0010 1010 == 42: Indicates that the UserID has only the permissions to enter the room and receive audio/video data.
 */
Api.prototype.genPrivateMapKeyWithStringRoomID = function (userid, expire, roomstr, privilegeMap) {
    var userBuf = this._genUserbuf(userid, 0, expire, privilegeMap, 0, roomstr);
    return this.genSig(userid, expire, userBuf);

};

exports.Api = Api;