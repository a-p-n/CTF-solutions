package main

import (
	"github.com/drand/kyber/pairing/bn254"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/sign/tbls"

	"fmt"
	"os"

	"ctf.polygl0ts.ch/thirtytwo"
)

const threshold = 3

func main() {
	if err := menu(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func menu() error {
	suite := bn254.NewSuite()
	scheme := tbls.NewThresholdSchemeOnG1(suite)
	dealer := thirtytwo.NewDealer(suite.G2(), 3)

	fmt.Printf("Public key: %s\n", dealer.GetPublicKey())

	var index dkg.Index
	fmt.Print("Please choose your index: ")
	if _, err := fmt.Scanf("%d\n", &index); err != nil {
		return err
	}
	fmt.Printf("You have chosen index %d\n", index)

	sk := dealer.DealShare(index)
	fmt.Printf("Here is your share: %s\n", sk.V)

	signers := make([]*share.PriShare, threshold-1)
	nextIndex := 1
	for i := range signers {
		if nextIndex == int(index) {
			nextIndex++
		}
		signers[i] = dealer.DealShare(dkg.Index(nextIndex))
		nextIndex++
	}

	msg := "hello world"
	fmt.Printf("The message is: %s\n", msg)

	for {
		actions := []string{"Submit Signature Share", "Get flag", "Exit"}
		for i, action := range actions {
			fmt.Printf("%d. %s\n", i+1, action)
		}
		fmt.Print("What would you like to do? ")
		var choice int
		if _, err := fmt.Scanf("%d\n", &choice); err != nil {
			return err
		}

		switch choice {
		case 1: // Submit signature share
			fmt.Print("Please enter your signature share: ")
			var share []byte
			if _, err := fmt.Scanf("%x\n", &share); err != nil {
				return err
			}
			if err := scheme.VerifyPartial(dealer.GetPubPoly(), []byte(msg), share); err != nil {
				return err
			}
			shares := [][]byte{share}
			for _, signer := range signers {
				share, err := scheme.Sign(signer, []byte(msg))
				if err != nil {
					return err
				}
				shares = append(shares, share)
			}
			sig, err := scheme.Recover(dealer.GetPubPoly(), []byte(msg), shares,3,0)
			if err != nil {
				return err
			}
			fmt.Printf("The signature is %x\n", sig)

		case 2: // Get flag
			fmt.Print("Please enter the signature: ")
			var sig []byte
			if _, err := fmt.Scanf("%x\n", &sig); err != nil {
				return err
			}
			if err := scheme.VerifyRecovered(dealer.GetPublicKey(), []byte("gimme flag"), sig); err != nil {
				return err
			}
			fmt.Printf("Here is the flag: %s\n", os.Getenv("FLAG"))
			return nil

		case 3:
			fmt.Println("Goodbye!")
			return nil

		default:
			fmt.Println("Invalid choice")
		}
	}

	return nil
}
