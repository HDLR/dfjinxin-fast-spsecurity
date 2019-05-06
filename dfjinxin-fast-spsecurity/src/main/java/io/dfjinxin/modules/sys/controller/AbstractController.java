/**
 * 2019 东方金信
 *
 *
 *
 *
 */

package io.dfjinxin.modules.sys.controller;

import io.dfjinxin.common.security.security.JwtUser;
import io.dfjinxin.common.security.utils.SecurityContextHolder;
import io.dfjinxin.modules.sys.entity.SysUserEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Controller公共组件
 *
 * @author Mark sunlightcs@gmail.com
 */
public abstract class AbstractController {
	protected Logger logger = LoggerFactory.getLogger(getClass());
	
//	protected SysUserEntity getUser() {
//		return (SysUserEntity) SecurityUtils.getSubject().getPrincipal();
//	}
	protected JwtUser getUser() {
		return (JwtUser)SecurityContextHolder.getUserDetails();
	}

	protected Long getUserId() {
		return getUser().getId();
	}
}
