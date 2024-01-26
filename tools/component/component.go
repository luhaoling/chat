// Copyright © 2023 OpenIM open source community. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package component

import (
	"fmt"
	"github.com/OpenIMSDK/tools/component"
	"time"

	"github.com/OpenIMSDK/chat/pkg/common/config"
)

func ComponentCheck() error {

	if config.Config.Envs.Discovery != "k8s" {
		checks := []component.CheckFunc{
			{Name: "Zookeeper", Function: component.CheckZookeeper, Config: config.Config.Zookeeper},
			{Name: "Redis", Function: component.CheckRedis, Config: config.Config.Redis},
			{Name: "MySQL", Function: component.CheckMySQL, Config: config.Config.Mysql},
		}

		for i := 0; i < component.MaxRetry; i++ {
			if i != 0 {
				time.Sleep(1 * time.Second)
			}
			fmt.Printf("Checking components Round %v...\n", i+1)

			allSuccess := true
			for _, check := range checks {
				str, err := check.Function(check.Config)
				if err != nil {
					component.ErrorPrint(fmt.Sprintf("Starting %s failed, %v", check.Name, err))
					allSuccess = false
					break
				} else {
					component.SuccessPrint(fmt.Sprintf("%s connected successfully, %s", check.Name, str))
				}
			}

			if allSuccess {
				component.SuccessPrint("All components started successfully!")
				return nil
			}
		}
	}
	return nil
}
