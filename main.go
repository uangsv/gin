package main

import (
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"github.com/golang-jwt/jwt/v4"
	"time"
	"fmt"
)

func main() {
	r := gin.Default()

	r.GET("", CheckJWTLogin(), func(c *gin.Context) {
		user, _ := c.Get("user")
		c.JSON(200, gin.H{
			"code": 200,
			"data": gin.H{"user": user},
		})
	}

	// https://juejin.cn/post/6977533940101808142
	r.POST("/user/register", func(c *gin.Context) {
		username := c.PostForm("username")
		telephone := c.PostForm("telephone")
		password := c.PostForm("password")

		hashedPassword,err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			panic(err)
		}
		fmt.Println(username,telephone,string(hashedPassword))

		fmt.Println("密码验证")
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte("123456"))
		fmt.Println(err)
		c.JSON(200, gin.H{
			"code": 200,
			"message": "注册成功",
			"data": gin.H{"username": username, "token":"token"},
		})
	})

	// https://juejin.cn/post/6977215050624794637
	r.POST("/user/login", func(c *gin.Context) {
		var user *UserInfo
		err := c.Bind(&user)
		if err != nil {
			c.JSON(200, gin.H{
				"code": 2001,
				"msg":  "无效的参数",
			})
		}
		// 校验用户名和密码是否正确
		// err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.password))
		if user.Telephone == "15223287564" && user.Password == "123456" {
			// 生成Token
			tokenString, _ := ReleaseToken(user)
			c.JSON(200, gin.H{
				"code": 2000,
				"msg":  "success",
				"data": gin.H{"token": tokenString},
			})
			return
		}
		c.JSON(200, gin.H{
			"code": 2002,
			"msg":  "鉴权失败",
		})
	})
	panic(r.Run())
}

type UserInfo struct {
	
	Telephone string `json:"telephone"`
	Password string `json:"password"`
} 

// 发放token
var jwtKey = []byte("apple")

type Claims struct {
	UserId int
	jwt.StandardClaims
}
// GenToken 生成JWT
func ReleaseToken(user *UserInfo) (tokenString string,err error) {
	expire := time.Now().Add(7 * 24 * time.Hour)
	claims := &Claims{
		UserId: 1,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expire.Unix(),
			IssuedAt: time.Now().Unix(),
			Issuer: "oceanlearn.tech",
			Subject: "user token",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err = token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}
	return
}

// 中间件
func CheckJWTLogin() gin.HandlerFunc  {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" || !strings.HasPrefix(tokenString, "Bearer "){
			c.JSON(401, gin.H{"code":401, "msg":"权限不足"})
			c.Abort()
			return
		}

		tokenString = tokenString[7:]
		_, claims, err := common.ParseToken(tokenString)
		if err != nil {
			c.JSON(419, gin.H{"code":419, "msg": err.Error()})
			c.Abort()
			return
		}

		// userId := claims.UserId
		// var user *UserInfo
		// dao.DB.First(&user, userId)
		// // 用户不存在
		// if user.ID == 0 {
		// 	c.JSON(401, gin.H{"code":401, "msg": "权限不足"})
		// 	c.Abort()
		// 	return
		// }
		// 用户存在 将用户写入上下文
		c.Set("user", "uangsv")
		c.Next()
	}
}

func ParseToken(tokenString string) (*jwt.Token, *Claims, error) {
	claims := &Claims{}
	token,err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	return token, claims, err
}
