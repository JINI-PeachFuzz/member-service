
package org.koreait.member.exceptions;

import org.koreait.global.exceptions.CommonException;
import org.springframework.http.HttpStatus;

public class TempTokenExpiredException extends CommonException {
    public TempTokenExpiredException() {
        super("Expired.tempToken", HttpStatus.UNAUTHORIZED);
        setErrorCode(true);
    }
}
