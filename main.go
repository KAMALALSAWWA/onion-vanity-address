package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const usage = `Usage:
    onion-vanity-address [--from PUBLIC_KEY] [--timeout TIMEOUT] PREFIX
    onion-vanity-address --offset OFFSET

Options:
    --from PUBLIC_KEY       Start search from a base64-encoded hs_ed25519_public_key.
    --offset OFFSET         Add an offset to a base64-encoded hs_ed25519_secret_key from standard input.
    --timeout TIMEOUT       Stop after the specified timeout (e.g., 10s, 5m, 1h).

onion-vanity-address generates a new hidden service ed25519 key pair with an onion address having the specified PREFIX,
and outputs it to standard output in base64-encoded YAML format.

PREFIX is transformed to lowercase and cannot contain the characters '0', '1', '8', and '9'.

In --from mode, onion-vanity-address starts the search from a specified public key and
outputs the offset to the public key with the desired prefix.
The offset can be added to the corresponding secret key to derive the new key pair.

In --offset mode, onion-vanity-address reads a base64-encoded hs_ed25519_secret_key from standard input,
adds the specified offset to it, and outputs the resulting key pair.

Examples:

    # Generate a new key pair with the specified prefix
    $ onion-vanity-address allium
    Found allium... in 12s after 558986486 attempts (48529996 attempts/s)
    ---
    hostname: alliumdye3it7ko4cuftoni4rlrupuobvio24ypz55qpzjzpvuetzhyd.onion
    hs_ed25519_public_key: PT0gZWQyNTUxOXYxLXB1YmxpYzogdHlwZTAgPT0AAAAC1ooweCbRP6ncFQs3NRyK40fRwaodrmH572D8py+tCQ==
    hs_ed25519_secret_key: PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAAAQEW4Rhot7oroPaETlAEG3GPAntvJ1agF2c7A2AXmBW3WqAH0oUZ1hySvvZl3hc9dSAIc49h1UuCPZacOWp4vQ

    # Find prefix offset from the specified public key
    $ onion-vanity-address --from PT0gZWQyNTUxOXYxLXB1YmxpYzogdHlwZTAgPT0AAAAC1ooweCbRP6ncFQs3NRyK40fRwaodrmH572D8py+tCQ== cebula
    Found cebula... in 2s after 78457550 attempts (44982483 attempts/s)
    ---
    hostname: cebulasfa3b4ahol44ydvc2an6b4vgpjcguarwsj35dr6jbanveea4id.onion
    offset: cIZ5Birj/cY=

    # Apply offset to the secret key
    $ echo PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAAAQEW4Rhot7oroPaETlAEG3GPAntvJ1agF2c7A2AXmBW3WqAH0oUZ1hySvvZl3hc9dSAIc49h1UuCPZacOWp4vQ \
    | onion-vanity-address --offset cIZ5Birj/cY=
    ---
    hostname: cebulasfa3b4ahol44ydvc2an6b4vgpjcguarwsj35dr6jbanxenrcqd.onion
    hs_ed25519_public_key: PT0gZWQyNTUxOXYxLXB1YmxpYzogdHlwZTAgPT0AAAARA0WCRQbDwB3L5zA6i0Bvg8qZ6RGoCNpJ30cfJCBtyA==
    hs_ed25519_secret_key: PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAABA/41ot1OvJr4PaETlAEG3GPAntvJ1agF2c7A2AXmBW/BnbLk2LgY3abEydc7heS5rhKByW/nafTlwifcgL0zO
`

func must[T any](v T, err error) T {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	return v
}

func main() {
	var fromFlag string
	var offsetFlag string
	var timeoutFlag time.Duration

	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.StringVar(&fromFlag, "from", "", "base64-encoded hs_ed25519_public_key to start search from")
	flag.StringVar(&offsetFlag, "offset", "", "base64-encoded offset to add to the secret key read from stdin")
	flag.DurationVar(&timeoutFlag, "timeout", 0, "stop after specified timeout")
	flag.Parse()

	if offsetFlag != "" {
		if fromFlag != "" {
			fmt.Fprintln(os.Stderr, "Error: --offset and --from can not be used together")
			flag.Usage()
			os.Exit(1)
		}
		if flag.NArg() != 0 {
			fmt.Fprintln(os.Stderr, "Error: --offset can not be used with PREFIX")
			flag.Usage()
			os.Exit(1)
		}
		startSecretKey := must(readStartSecretKey())
		offset := new(big.Int).SetBytes(must(base64.StdEncoding.DecodeString(offsetFlag)))

		vanitySecretKey := must(add(startSecretKey, offset))
		vanityPublicKey := must(publicKeyFor(vanitySecretKey))

		fmt.Println("---")
		fmt.Printf("%s: %s\n", hostnameFileName, encodeOnionAddress(vanityPublicKey))
		fmt.Printf("%s: %s\n", publicKeyFileName, base64.StdEncoding.EncodeToString(encodePublicKey(vanityPublicKey)))
		fmt.Printf("%s: %s\n", secretKeyFileName, base64.StdEncoding.EncodeToString(encodeSecretKey(vanitySecretKey)))
		return
	}

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "Error: PREFIX required")
		flag.Usage()
		os.Exit(1)
	}

	prefix := flag.Arg(0)

	var startSecretKey, startPublicKey []byte
	if fromFlag != "" {
		spkb := must(base64.StdEncoding.DecodeString(fromFlag))
		startPublicKey = must(decodePublicKey(spkb))
	} else {
		startSecretKey = make([]byte, 32)
		rand.Read(startSecretKey)

		startPublicKey = must(publicKeyFor(startSecretKey))
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if timeoutFlag > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeoutFlag)
		defer cancel()
	}

	start := time.Now()
	found, vanityPublicKey, attempts := searchParallel(ctx, startPublicKey, must(match(prefix)))
	elapsed := time.Since(start)

	if found != nil {
		var vanitySecretKey []byte
		if len(startSecretKey) > 0 {
			vanitySecretKey = must(add(startSecretKey, found))
			vanityPublicKey = must(publicKeyFor(vanitySecretKey))
		}

		fmt.Fprintf(os.Stderr, "Found %s... in %s after %d attempts (%.0f attempts/s)\n",
			prefix, elapsed.Round(time.Second), attempts, float64(attempts)/elapsed.Seconds())

		fmt.Println("---")
		fmt.Printf("%s: %s\n", hostnameFileName, encodeOnionAddress(vanityPublicKey))
		if len(vanitySecretKey) > 0 {
			fmt.Printf("%s: %s\n", publicKeyFileName, base64.StdEncoding.EncodeToString(encodePublicKey(vanityPublicKey)))
			fmt.Printf("%s: %s\n", secretKeyFileName, base64.StdEncoding.EncodeToString(encodeSecretKey(vanitySecretKey)))
		} else {
			fmt.Printf("offset: %s\n", base64.StdEncoding.EncodeToString(found.Bytes()))
		}
	} else {
		fmt.Fprintf(os.Stderr, "Stopped searching %s... after %s and %d attempts (%.0f attempts/s)\n",
			prefix, elapsed.Round(time.Second), attempts, float64(attempts)/elapsed.Seconds())
		os.Exit(2)
	}
}

func match(prefix string) (func([]byte) bool, error) {
	if len(prefix) == 0 {
		return nil, fmt.Errorf("empty prefix")
	}

	prefix = strings.ToLower(prefix)
	if strings.TrimLeft(prefix, onionBase32EncodingCharset) != "" {
		return nil, fmt.Errorf("prefix must use characters %q", onionBase32EncodingCharset)
	}

	prefixBytes, bits, err := decodePrefixBits(prefix)
	if err != nil {
		return nil, err
	}
	return hasPrefixBits(prefixBytes, bits), nil
}

func searchParallel(ctx context.Context, startPublicKey []byte, test func([]byte) bool) (*big.Int, []byte, uint64) {
	var result atomic.Pointer[big.Int]
	var vanityPublicKey []byte

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var attemptsTotal atomic.Uint64
	var wg sync.WaitGroup
	for range runtime.NumCPU() {
		wg.Go(func() {
			startOffset, _ := rand.Int(rand.Reader, new(big.Int).SetUint64(1<<64-1))
			attempts := search(ctx, startPublicKey, startOffset, 4096, test, func(pk []byte, offset *big.Int) {
				if result.CompareAndSwap(nil, offset) {
					vanityPublicKey = pk
					cancel()
				}
			})
			attemptsTotal.Add(attempts)
		})
	}
	wg.Wait()

	return result.Load(), vanityPublicKey, attemptsTotal.Load()
}

func readStartSecretKey() ([]byte, error) {
	limit := int64(base64.StdEncoding.EncodedLen(secretKeyFileLength))
	encoded, err := io.ReadAll(io.LimitReader(os.Stdin, limit))
	if err != nil {
		return nil, err
	}
	decoded := make([]byte, secretKeyFileLength)
	if _, err := base64.StdEncoding.Decode(decoded, encoded); err != nil {
		return nil, err
	}
	return decodeSecretKey(decoded)
}
