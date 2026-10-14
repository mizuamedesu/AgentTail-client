package platform

import "os"

func Signals() []os.Signal { return []os.Signal{os.Interrupt} }
