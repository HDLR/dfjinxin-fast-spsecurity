/**
 * 2019 东方金信
 *
 *
 *
 *
 */

package io.dfjinxin.modules.sys.controller;

import io.dfjinxin.common.security.security.JwtUser;
import io.dfjinxin.common.security.utils.EncryptUtils;
import io.dfjinxin.common.security.utils.JwtTokenUtil;
import io.dfjinxin.common.utils.R;
import io.dfjinxin.modules.sys.entity.SysUserEntity;
import io.dfjinxin.modules.sys.form.SysLoginForm;
import io.dfjinxin.modules.sys.service.SysCaptchaService;
import io.dfjinxin.modules.sys.service.SysUserService;
import io.dfjinxin.modules.sys.service.SysUserTokenService;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.imageio.ImageIO;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.util.Map;

/**
 * 登录相关
 *
 * @author Mark sunlightcs@gmail.com
 */
@RestController
public class SysLoginController extends AbstractController {
	@Autowired
	@Qualifier("jwtUserDetailsService")
	private UserDetailsService userDetailsService;

	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	@Autowired
	private SysCaptchaService sysCaptchaService;

	/**
	 * 验证码
	 */
	@GetMapping("captcha.jpg")
	public void captcha(HttpServletResponse response, String uuid)throws IOException {
		response.setHeader("Cache-Control", "no-store, no-cache");
		response.setContentType("image/jpeg");

		//获取图片验证码
		BufferedImage image = sysCaptchaService.getCaptcha(uuid);

		ServletOutputStream out = response.getOutputStream();
		ImageIO.write(image, "jpg", out);
		IOUtils.closeQuietly(out);
	}

	/**
	 * 登录
	 */
	@PostMapping("/sys/login")
	public Map<String, Object> login(@RequestBody SysLoginForm form)throws IOException {
//		boolean captcha = sysCaptchaService.validate(form.getUuid(), form.getCaptcha());
//		if(!captcha){
//			return R.error("验证码不正确");
//		}

		//用户信息
		final JwtUser jwtUser = (JwtUser) userDetailsService.loadUserByUsername(form.getUsername());

		//账号不存在、密码错误

		if(jwtUser == null || !jwtUser.getPassword().equals(EncryptUtils.encryptPassword(form.getPassword()))) {
			return R.error("账号或密码不正确");
		}

		//账号锁定
		if(!jwtUser.isEnabled()){
			return R.error("账号已被锁定,请联系管理员");
		}

		//生成token，并保存到数据库
		// 生成令牌
		final String token = jwtTokenUtil.generateToken(jwtUser);
		R r = R.ok().put("token", token);
		return r;
	}


	/**
	 * 退出
	 */
	@PostMapping("/sys/logout")
	public R logout() {
//		sysUserTokenService.logout(getUserId());
		return R.ok();
	}
}
