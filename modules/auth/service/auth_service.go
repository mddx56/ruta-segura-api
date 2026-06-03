package service

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/Caknoooo/go-gin-clean-starter/database/entities"
	appDto "github.com/Caknoooo/go-gin-clean-starter/modules/app_version/dto"
	appRepo "github.com/Caknoooo/go-gin-clean-starter/modules/app_version/repository"
	"github.com/Caknoooo/go-gin-clean-starter/modules/auth/dto"
	authRepo "github.com/Caknoooo/go-gin-clean-starter/modules/auth/repository"
	userDto "github.com/Caknoooo/go-gin-clean-starter/modules/user/dto"
	"github.com/Caknoooo/go-gin-clean-starter/modules/user/repository"
	"github.com/Caknoooo/go-gin-clean-starter/pkg/constants"
	"github.com/Caknoooo/go-gin-clean-starter/pkg/helpers"
	"github.com/Caknoooo/go-gin-clean-starter/pkg/utils"
	redisProvider "github.com/Caknoooo/go-gin-clean-starter/providers/redis"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

const loginMaxAttempts = 5

func loginAttemptsKey(identifier string) string {
	return "login:attempts:" + strings.ToLower(identifier)
}

type AuthService interface {
	Register(ctx context.Context, req userDto.UserCreateRequest) (userDto.UserResponse, error)
	Signup(ctx context.Context, req userDto.UserCreateRequest) (userDto.UserResponse, error)
	Login(ctx context.Context, req userDto.UserLoginRequest) (dto.TokenResponse, error)
	RefreshToken(ctx context.Context, req dto.RefreshTokenRequest) (dto.TokenResponse, error)
	Logout(ctx context.Context, userId string) error
	SendVerificationEmail(ctx context.Context, req userDto.SendVerificationEmailRequest) error
	VerifyEmail(ctx context.Context, req userDto.VerifyEmailRequest) (userDto.VerifyEmailResponse, error)
	SendPasswordReset(ctx context.Context, req dto.SendPasswordResetRequest) error
	ResetPassword(ctx context.Context, req dto.ResetPasswordRequest) error
}

type authService struct {
	userRepository         repository.UserRepository
	refreshTokenRepository authRepo.RefreshTokenRepository
	appVersionRepository   appRepo.AppVersionRepository
	jwtService             JWTService
	redis                  redisProvider.RedisService
	db                     *gorm.DB
}

func NewAuthService(
	userRepo repository.UserRepository,
	refreshTokenRepo authRepo.RefreshTokenRepository,
	appVersionRepo appRepo.AppVersionRepository,
	jwtService JWTService,
	redis redisProvider.RedisService,
	db *gorm.DB,
) AuthService {
	return &authService{
		userRepository:         userRepo,
		refreshTokenRepository: refreshTokenRepo,
		appVersionRepository:   appVersionRepo,
		jwtService:             jwtService,
		redis:                  redis,
		db:                     db,
	}
}

// checkLoginRateLimit devuelve ErrLoginRateLimited si la clave superó el umbral.
// Ante cualquier error de Redis falla abierto (no bloquea al usuario).
func (s *authService) checkLoginRateLimit(ctx context.Context, key string) error {
	if s.redis == nil {
		return nil
	}
	count, exists, err := s.redis.GetInt(ctx, key)
	if err != nil {
		log.Printf("[rate-limit] error al consultar Redis: %v", err)
		return nil
	}
	if exists && count >= loginMaxAttempts {
		return dto.ErrLoginRateLimited
	}
	return nil
}

// incrementLoginAttempts registra un intento fallido con ventana deslizante de 15 min.
func (s *authService) incrementLoginAttempts(ctx context.Context, key string) {
	if s.redis == nil {
		return
	}
	if _, err := s.redis.IncrWithTTL(ctx, key, 15*time.Minute); err != nil {
		log.Printf("[rate-limit] error al incrementar intentos en Redis: %v", err)
	}
}

func (s *authService) Register(ctx context.Context, req userDto.UserCreateRequest) (userDto.UserResponse, error) {
	_, isExist, err := s.userRepository.CheckEmail(ctx, s.db, req.Email)
	if err != nil && err != gorm.ErrRecordNotFound {
		return userDto.UserResponse{}, err
	}

	if isExist {
		return userDto.UserResponse{}, userDto.ErrEmailAlreadyExists
	}

	user := entities.User{
		ID:         uuid.New(),
		Name:       req.Name,
		Username:   &req.Username,
		Email:      req.Email,
		TelpNumber: req.TelpNumber,
		Password:   req.Password,
		Role:       constants.ENUM_ROLE_ADMIN,
		IsVerified: false,
	}

	createdUser, err := s.userRepository.Register(ctx, s.db, user)
	if err != nil {
		return userDto.UserResponse{}, err
	}

	return userDto.UserResponse{
		ID:          createdUser.ID.String(),
		Name:        createdUser.Name,
		Username:    createdUser.Username,
		Email:       createdUser.Email,
		TelpNumber:  createdUser.TelpNumber,
		Role:        createdUser.Role,
		RoleLiteral: constants.RoleLiteral(createdUser.Role),
		ImageUrl:    createdUser.ImageUrl,
		IsVerified:  createdUser.IsVerified,
		IsBlocked:   createdUser.IsBlocked,
	}, nil
}

func (s *authService) Signup(ctx context.Context, req userDto.UserCreateRequest) (userDto.UserResponse, error) {
	_, isExist, err := s.userRepository.CheckEmail(ctx, s.db, req.Email)
	if err != nil && err != gorm.ErrRecordNotFound {
		return userDto.UserResponse{}, err
	}
	if isExist {
		return userDto.UserResponse{}, userDto.ErrEmailAlreadyExists
	}

	user := entities.User{
		ID:         uuid.New(),
		Name:       req.Name,
		Username:   &req.Username,
		Email:      req.Email,
		TelpNumber: req.TelpNumber,
		Password:   req.Password,
		Role:       constants.ENUM_ROLE_USER,
		IsVerified: false,
	}

	createdUser, err := s.userRepository.Register(ctx, s.db, user)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			if strings.Contains(pgErr.ConstraintName, "username") {
				return userDto.UserResponse{}, userDto.ErrUsernameAlreadyExists
			}
			if strings.Contains(pgErr.ConstraintName, "email") {
				return userDto.UserResponse{}, userDto.ErrEmailAlreadyExists
			}
		}
		return userDto.UserResponse{}, err
	}

	return userDto.UserResponse{
		ID:          createdUser.ID.String(),
		Name:        createdUser.Name,
		Username:    createdUser.Username,
		Email:       createdUser.Email,
		TelpNumber:  createdUser.TelpNumber,
		Role:        createdUser.Role,
		RoleLiteral: constants.RoleLiteral(createdUser.Role),
		ImageUrl:    createdUser.ImageUrl,
		IsVerified:  createdUser.IsVerified,
		IsBlocked:   createdUser.IsBlocked,
	}, nil
}

func (s *authService) Login(ctx context.Context, req userDto.UserLoginRequest) (dto.TokenResponse, error) {
	identifier := ""
	if req.Email != nil && *req.Email != "" {
		identifier = *req.Email
	} else if req.Username != nil && *req.Username != "" {
		identifier = *req.Username
	}

	key := loginAttemptsKey(identifier)

	// Verificar rate limit antes de tocar la base de datos
	if err := s.checkLoginRateLimit(ctx, key); err != nil {
		return dto.TokenResponse{}, err
	}

	user, err := s.userRepository.GetUserByUsernameOrEmail(ctx, s.db, identifier)
	if err != nil {
		s.incrementLoginAttempts(ctx, key)
		return dto.TokenResponse{}, userDto.ErrUserNotFound
	}

	if !user.Status {
		return dto.TokenResponse{}, dto.ErrUserDisabled
	}

	if user.IsBlocked {
		return dto.TokenResponse{}, dto.ErrUserBlocked
	}

	isValid, err := helpers.CheckPassword(user.Password, []byte(req.Password))
	if err != nil || !isValid {
		s.incrementLoginAttempts(ctx, key)
		return dto.TokenResponse{}, dto.ErrInvalidCredentials
	}

	// Login exitoso → limpiar contador
	if s.redis != nil {
		if err := s.redis.Delete(ctx, key); err != nil {
			log.Printf("[rate-limit] error al limpiar intentos en Redis: %v", err)
		}
	}

	accessToken := s.jwtService.GenerateAccessToken(user.ID.String(), user.Role)
	refreshTokenString, expiresAt := s.jwtService.GenerateRefreshToken()

	refreshToken := entities.RefreshToken{
		ID:        uuid.New(),
		UserID:    user.ID,
		Token:     refreshTokenString,
		ExpiresAt: expiresAt,
	}

	_, err = s.refreshTokenRepository.Create(ctx, s.db, refreshToken)
	if err != nil {
		return dto.TokenResponse{}, err
	}

	var appResponse *appDto.AppVersionResponse
	appVersion, err := s.appVersionRepository.GetLatestVersion(ctx, s.db)
	if err == nil {
		appResponse = &appDto.AppVersionResponse{
			AppId:                appVersion.AppId,
			VersionName:          appVersion.VersionName,
			VersionCode:          appVersion.VersionCode,
			UrlPlaystore:         appVersion.UrlPlaystore,
			UrlApplestore:        appVersion.UrlApplestore,
			FechaRelease:         appVersion.FechaRelease,
			MiniSupportedVersion: appVersion.MiniSupportedVersion,
			IsForceUpdate:        appVersion.IsForceUpdate,
			Plataform:            appVersion.Plataform,
			CreatedAt:            appVersion.CreatedAt,
			UpdatedAt:            appVersion.UpdatedAt,
		}
	}

	return dto.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshTokenString,
		User: userDto.UserResponse{
			ID:         user.ID.String(),
			Name:       user.Name,
			Username:   user.Username,
			Email:      user.Email,
			TelpNumber: user.TelpNumber,
			Role:       user.Role,
			RoleLiteral: constants.RoleLiteral(user.Role),
			ImageUrl:   user.ImageUrl,
			IsVerified: user.IsVerified,
			IsBlocked:  user.IsBlocked,
			Status:     user.Status,
		},
		App: appResponse,
	}, nil
}

func (s *authService) RefreshToken(ctx context.Context, req dto.RefreshTokenRequest) (dto.TokenResponse, error) {
	refreshToken, err := s.refreshTokenRepository.FindByToken(ctx, s.db, req.RefreshToken)
	if err != nil {
		return dto.TokenResponse{}, dto.ErrRefreshTokenNotFound
	}

	if !refreshToken.User.Status {
		return dto.TokenResponse{}, dto.ErrUserDisabled
	}

	if refreshToken.User.IsBlocked {
		return dto.TokenResponse{}, dto.ErrUserBlocked
	}

	accessToken := s.jwtService.GenerateAccessToken(refreshToken.UserID.String(), refreshToken.User.Role)
	newRefreshTokenString, expiresAt := s.jwtService.GenerateRefreshToken()

	err = s.refreshTokenRepository.DeleteByToken(ctx, s.db, req.RefreshToken)
	if err != nil {
		return dto.TokenResponse{}, err
	}

	newRefreshToken := entities.RefreshToken{
		ID:        uuid.New(),
		UserID:    refreshToken.UserID,
		Token:     newRefreshTokenString,
		ExpiresAt: expiresAt,
	}

	_, err = s.refreshTokenRepository.Create(ctx, s.db, newRefreshToken)
	if err != nil {
		return dto.TokenResponse{}, err
	}

	var appResponse *appDto.AppVersionResponse
	appVersion, err := s.appVersionRepository.GetLatestVersion(ctx, s.db)
	if err == nil {
		appResponse = &appDto.AppVersionResponse{
			AppId:                appVersion.AppId,
			VersionName:          appVersion.VersionName,
			VersionCode:          appVersion.VersionCode,
			UrlPlaystore:         appVersion.UrlPlaystore,
			UrlApplestore:        appVersion.UrlApplestore,
			FechaRelease:         appVersion.FechaRelease,
			MiniSupportedVersion: appVersion.MiniSupportedVersion,
			IsForceUpdate:        appVersion.IsForceUpdate,
			Plataform:            appVersion.Plataform,
			CreatedAt:            appVersion.CreatedAt,
			UpdatedAt:            appVersion.UpdatedAt,
		}
	}

	return dto.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshTokenString,
		User: userDto.UserResponse{
			ID:         refreshToken.User.ID.String(),
			Name:       refreshToken.User.Name,
			Username:   refreshToken.User.Username,
			Email:      refreshToken.User.Email,
			TelpNumber: refreshToken.User.TelpNumber,
			Role:       refreshToken.User.Role,
			RoleLiteral: constants.RoleLiteral(refreshToken.User.Role),
			ImageUrl:   refreshToken.User.ImageUrl,
			IsVerified: refreshToken.User.IsVerified,
			IsBlocked:  refreshToken.User.IsBlocked,
			Status:     refreshToken.User.Status,
		},
		App: appResponse,
	}, nil
}

func (s *authService) Logout(ctx context.Context, userId string) error {
	return s.refreshTokenRepository.DeleteByUserID(ctx, s.db, userId)
}

func (s *authService) SendVerificationEmail(ctx context.Context, req userDto.SendVerificationEmailRequest) error {
	user, err := s.userRepository.GetUserByEmail(ctx, s.db, req.Email)
	if err != nil {
		return userDto.ErrEmailNotFound
	}

	if user.IsVerified {
		return userDto.ErrAccountAlreadyVerified
	}

	verificationToken := s.jwtService.GenerateAccessToken(user.ID.String(), "verification")

	subject := "Email Verification"
	body := "Please verify your email using this token: " + verificationToken

	return utils.SendMail(user.Email, subject, body)
}

func (s *authService) VerifyEmail(ctx context.Context, req userDto.VerifyEmailRequest) (userDto.VerifyEmailResponse, error) {
	token, err := s.jwtService.ValidateToken(req.Token)
	if err != nil || !token.Valid {
		return userDto.VerifyEmailResponse{}, userDto.ErrTokenInvalid
	}

	userId, err := s.jwtService.GetUserIDByToken(req.Token)
	if err != nil {
		return userDto.VerifyEmailResponse{}, userDto.ErrTokenInvalid
	}

	user, err := s.userRepository.GetUserById(ctx, s.db, userId)
	if err != nil {
		return userDto.VerifyEmailResponse{}, userDto.ErrUserNotFound
	}

	user.IsVerified = true
	updatedUser, err := s.userRepository.Update(ctx, s.db, user)
	if err != nil {
		return userDto.VerifyEmailResponse{}, err
	}

	return userDto.VerifyEmailResponse{
		Email:      updatedUser.Email,
		IsVerified: updatedUser.IsVerified,
	}, nil
}

func (s *authService) SendPasswordReset(ctx context.Context, req dto.SendPasswordResetRequest) error {
	user, err := s.userRepository.GetUserByEmail(ctx, s.db, req.Email)
	if err != nil {
		return userDto.ErrEmailNotFound
	}

	resetToken := s.jwtService.GenerateAccessToken(user.ID.String(), "password_reset")

	subject := "Password Reset"
	body := "Please reset your password using this token: " + resetToken

	return utils.SendMail(user.Email, subject, body)
}

func (s *authService) ResetPassword(ctx context.Context, req dto.ResetPasswordRequest) error {
	token, err := s.jwtService.ValidateToken(req.Token)
	if err != nil || !token.Valid {
		return dto.ErrPasswordResetToken
	}

	userId, err := s.jwtService.GetUserIDByToken(req.Token)
	if err != nil {
		return dto.ErrPasswordResetToken
	}

	user, err := s.userRepository.GetUserById(ctx, s.db, userId)
	if err != nil {
		return userDto.ErrUserNotFound
	}

	hashedPassword, err := helpers.HashPassword(req.NewPassword)
	if err != nil {
		return err
	}

	user.Password = hashedPassword
	_, err = s.userRepository.Update(ctx, s.db, user)
	if err != nil {
		return err
	}

	return nil
}
