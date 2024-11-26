package core

import (
	"fmt"
	"testing"
)

func TestTryConnectServerV2(t *testing.T) {
	type args struct {
		ipPort   string
		password string
		user     string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		//	检测错误类型
		{
			name: "tcp连接失败",
			args: args{
				ipPort:   "127.0.0.1:2222",
				password: "password",
				user:     "root",
			},
			wantErr: true,
		},
		{
			name: "单纯的密码错误",
			// todo
			args: args{
				ipPort:   "192.168.3.108:22",
				password: "qwer123",
				user:     "kylin",
			},
			wantErr: true,
		},
		{
			name: "正确",
			// todo
			args: args{
				ipPort:   "192.168.3.108:22",
				password: "qwer1234",
				user:     "kylin",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := TryConnectServerV2(tt.args.ipPort, tt.args.password, tt.args.user); (err != nil) != tt.wantErr {
				t.Errorf("TryConnectServerV2() error = %v, wantErr %v", err, tt.wantErr)
				fmt.Printf("type:%T, value:%v\n", err, err)
			} else {
				fmt.Printf("type:%T, value:%v\n", err, err)
			}
		})
	}
}
