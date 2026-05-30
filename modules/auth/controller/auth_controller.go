package controller

import (
	"errors"
	"net/http"
	"strings"

	authDto "github.com/Caknoooo/go-gin-clean-starter/modules/auth/dto"
	"github.com/Caknoooo/go-gin-clean-starter/modules/auth/service"
	"github.com/Caknoooo/go-gin-clean-starter/modules/auth/validation"
	"github.com/Caknoooo/go-gin-clean-starter/modules/user/dto"
	"github.com/Caknoooo/go-gin-clean-starter/pkg/constants"
	"github.com/Caknoooo/go-gin-clean-starter/pkg/utils"
	"github.com/gin-gonic/gin"
	"github.com/samber/do"
	"github.com/go-playground/validator/v10"
	"gorm.io/gorm"
)

func formatValidationError(err error) string {
	var valErrs validator.ValidationErrors
	if errors.As(err, &valErrs) {
		var errMsgs []string
		for _, e := range valErrs {
			if e.Field() == "Password" && (e.Tag() == "min" || e.Tag() == "password") {
				errMsgs = append(errMsgs, "el minimo es 4 para contraseña")
			} else {
				errMsgs = append(errMsgs, e.Error())
			}
		}
		return strings.Join(errMsgs, ", ")
	}
	return err.Error()
}

type (
	AuthController interface {
		Register(ctx *gin.Context)
		Login(ctx *gin.Context)
		RefreshToken(ctx *gin.Context)
		Logout(ctx *gin.Context)
		SendVerificationEmail(ctx *gin.Context)
		VerifyEmail(ctx *gin.Context)
		SendPasswordReset(ctx *gin.Context)
		ResetPassword(ctx *gin.Context)
	}

	authController struct {
		authService    service.AuthService
		authValidation *validation.AuthValidation
		db             *gorm.DB
	}
)

func NewAuthController(injector *do.Injector, as service.AuthService) AuthController {
	db := do.MustInvokeNamed[*gorm.DB](injector, constants.DB)
	authValidation := validation.NewAuthValidation()
	return &authController{
		authService:    as,
		authValidation: authValidation,
		db:             db,
	}
}

// Register godoc
// @Summary      Register a new user
// @Description  Register a new user with the input payload
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        register  body      dto.UserCreateRequest  true  "Register Request"
// @Success      200       {object}  utils.Response
// @Failure      400       {object}  utils.Response
// @Router       /api/auth/register [post]
func (c *authController) Register(ctx *gin.Context) {
	var req dto.UserCreateRequest
	if err := ctx.ShouldBind(&req); err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_DATA_FROM_BODY, formatValidationError(err), nil)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

	// Validate request
	if err := c.authValidation.ValidateRegisterRequest(req); err != nil {
		res := utils.BuildResponseFailed("Validation failed", formatValidationError(err), nil)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

	result, err := c.authService.Register(ctx.Request.Context(), req)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_REGISTER_USER, err.Error(), nil)
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	res := utils.BuildResponseSuccess(dto.MESSAGE_SUCCESS_REGISTER_USER, result)
	ctx.JSON(http.StatusOK, res)
}

// Login godoc
// @Summary      Login user
// @Description  Login user with email and password
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        login  body      dto.UserLoginRequest  true  "Login Request"
// @Success      200    {object}  utils.Response
// @Failure      400    {object}  utils.Response
// @Router       /api/auth/login [post]
func (c *authController) Login(ctx *gin.Context) {
	var req dto.UserLoginRequest
	if err := ctx.ShouldBind(&req); err != nil {
		response := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_DATA_FROM_BODY, err.Error(), nil)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, response)
		return
	}

	// Validate request
	if err := c.authValidation.ValidateLoginRequest(req); err != nil {
		res := utils.BuildResponseFailed("Validation failed", err.Error(), nil)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

	result, err := c.authService.Login(ctx.Request.Context(), req)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_LOGIN, err.Error(), nil)
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	res := utils.BuildResponseSuccess(dto.MESSAGE_SUCCESS_LOGIN, result)
	ctx.JSON(http.StatusOK, res)
}

// RefreshToken godoc
// @Summary      Refresh access token
// @Description  Refresh access token using refresh token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        refresh  body      dto.RefreshTokenRequest  true  "Refresh Token Request"
// @Success      200      {object}  utils.Response
// @Failure      400      {object}  utils.Response
// @Failure      401      {object}  utils.Response
// @Router       /api/auth/refresh [post]
func (c *authController) RefreshToken(ctx *gin.Context) {
	var req authDto.RefreshTokenRequest
	if err := ctx.ShouldBind(&req); err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_DATA_FROM_BODY, err.Error(), nil)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

	result, err := c.authService.RefreshToken(ctx.Request.Context(), req)
	if err != nil {
		res := utils.BuildResponseFailed(authDto.MESSAGE_FAILED_REFRESH_TOKEN, err.Error(), nil)
		ctx.JSON(http.StatusUnauthorized, res)
		return
	}

	res := utils.BuildResponseSuccess(authDto.MESSAGE_SUCCESS_REFRESH_TOKEN, result)
	ctx.JSON(http.StatusOK, res)
}

// Logout godoc
// @Summary      Logout user
// @Description  Logout user and invalidate token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  utils.Response
// @Failure      400  {object}  utils.Response
// @Router       /api/auth/logout [post]
func (c *authController) Logout(ctx *gin.Context) {
	userId := ctx.MustGet("user_id").(string)

	err := c.authService.Logout(ctx.Request.Context(), userId)
	if err != nil {
		res := utils.BuildResponseFailed(authDto.MESSAGE_FAILED_LOGOUT, err.Error(), nil)
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	res := utils.BuildResponseSuccess(authDto.MESSAGE_SUCCESS_LOGOUT, nil)
	ctx.JSON(http.StatusOK, res)
}

// SendVerificationEmail godoc
// @Summary      Send verification email
// @Description  Send verification email to user
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        email  body      dto.SendVerificationEmailRequest  true  "Send Verification Email Request"
// @Success      200    {object}  utils.Response
// @Failure      400    {object}  utils.Response
// @Router       /api/auth/send-verification-email [post]
func (c *authController) SendVerificationEmail(ctx *gin.Context) {
	var req dto.SendVerificationEmailRequest
	if err := ctx.ShouldBind(&req); err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_DATA_FROM_BODY, err.Error(), nil)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

	err := c.authService.SendVerificationEmail(ctx.Request.Context(), req)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_PROSES_REQUEST, err.Error(), nil)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

	res := utils.BuildResponseSuccess(dto.MESSAGE_SEND_VERIFICATION_EMAIL_SUCCESS, nil)
	ctx.JSON(http.StatusOK, res)
}

// VerifyEmail godoc
// @Summary      Verify email
// @Description  Verify user email
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        verify  body      dto.VerifyEmailRequest  true  "Verify Email Request"
// @Success      200     {object}  utils.Response
// @Failure      400     {object}  utils.Response
// @Router       /api/auth/verify-email [post]
func (c *authController) VerifyEmail(ctx *gin.Context) {
	var req dto.VerifyEmailRequest
	if err := ctx.ShouldBind(&req); err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_DATA_FROM_BODY, err.Error(), nil)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

	result, err := c.authService.VerifyEmail(ctx.Request.Context(), req)
	if err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_VERIFY_EMAIL, err.Error(), nil)
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	res := utils.BuildResponseSuccess(dto.MESSAGE_SUCCESS_VERIFY_EMAIL, result)
	ctx.JSON(http.StatusOK, res)
}

// SendPasswordReset godoc
// @Summary      Send password reset email
// @Description  Send password reset email to user
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        email  body      dto.SendPasswordResetRequest  true  "Send Password Reset Request"
// @Success      200    {object}  utils.Response
// @Failure      400    {object}  utils.Response
// @Router       /api/auth/send-password-reset [post]
func (c *authController) SendPasswordReset(ctx *gin.Context) {
	var req authDto.SendPasswordResetRequest
	if err := ctx.ShouldBind(&req); err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_DATA_FROM_BODY, err.Error(), nil)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

	err := c.authService.SendPasswordReset(ctx.Request.Context(), req)
	if err != nil {
		res := utils.BuildResponseFailed(authDto.MESSAGE_FAILED_SEND_PASSWORD_RESET, err.Error(), nil)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

	res := utils.BuildResponseSuccess(authDto.MESSAGE_SUCCESS_SEND_PASSWORD_RESET, nil)
	ctx.JSON(http.StatusOK, res)
}

// ResetPassword godoc
// @Summary      Reset password
// @Description  Reset user password
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        reset  body      dto.ResetPasswordRequest  true  "Reset Password Request"
// @Success      200    {object}  utils.Response
// @Failure      400    {object}  utils.Response
// @Router       /api/auth/reset-password [post]
func (c *authController) ResetPassword(ctx *gin.Context) {
	var req authDto.ResetPasswordRequest
	if err := ctx.ShouldBind(&req); err != nil {
		res := utils.BuildResponseFailed(dto.MESSAGE_FAILED_GET_DATA_FROM_BODY, err.Error(), nil)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, res)
		return
	}

	err := c.authService.ResetPassword(ctx.Request.Context(), req)
	if err != nil {
		res := utils.BuildResponseFailed(authDto.MESSAGE_FAILED_RESET_PASSWORD, err.Error(), nil)
		ctx.JSON(http.StatusBadRequest, res)
		return
	}

	res := utils.BuildResponseSuccess(authDto.MESSAGE_SUCCESS_RESET_PASSWORD, nil)
	ctx.JSON(http.StatusOK, res)
}
