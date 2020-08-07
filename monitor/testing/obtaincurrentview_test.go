//Test file to see if the correct non-mirrored logs are pushed through.
//it ain't pretty

package main

import (
	"fmt"
)

func main() {

	log_id_list := []int64{12334, 234456, 34567}
	mirroring_list := []bool{false, true, false}

	if len(mirroring_list) == len(log_id_list) {
		for i, j := 0, 0; i < len(log_id_list); i, j = i+1, j+1 {
			if mirroring_list[j] == false { //if mirroring list contains a false value then run the update view
				fmt.Printf("The log_id list is %d \n", log_id_list[i])
			}
		}
	}
}

