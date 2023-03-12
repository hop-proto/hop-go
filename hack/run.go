// hack to run Hop in docker
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"
	"github.com/sirupsen/logrus"

	"hop.computer/hop/hack/data"
)

func buildContainer(ctx context.Context, c *client.Client, dFile string, id string) error {
	// This only works because the Dockerfile is in the same root as the container.
	path := filepath.Join(data.Workspace(), "containers")
	t, err := archive.TarWithOptions(path, &archive.TarOptions{})
	if err != nil {
		return err
	}
	res, err := c.ImageBuild(ctx, t, types.ImageBuildOptions{
		Dockerfile: dFile,
		Tags:       []string{id},
		Remove:     true,
	})
	if err != nil {
		return err
	}
	defer res.Body.Close()
	io.Copy(os.Stdout, res.Body)
	return nil
}

func runContainer(ctx context.Context, c *client.Client, id string, hostport string) error {
	containerConfig := container.Config{
		Image:        id,
		Volumes:      map[string]struct{}{"/app": {}},
		ExposedPorts: nat.PortSet{"77/udp": {}, "22/tcp": {}},
	}
	hostConfig := container.HostConfig{
		Mounts: []mount.Mount{
			{
				Type:     mount.TypeBind,
				Source:   data.Workspace(),
				Target:   "/app",
				ReadOnly: false,
			},
		},
		PortBindings: nat.PortMap{
			"77/udp": []nat.PortBinding{{HostIP: "127.0.0.1", HostPort: hostport}},
			"22/tcp": []nat.PortBinding{{HostIP: "127.0.0.1", HostPort: hostport}},
		},
		AutoRemove: true,
	}
	res, err := c.ContainerCreate(ctx, &containerConfig, &hostConfig, nil, nil, "")
	if err != nil {
		return err
	}
	if err := c.ContainerStart(ctx, res.ID, types.ContainerStartOptions{}); err != nil {
		return err
	}
	out, err := c.ContainerLogs(ctx, res.ID, types.ContainerLogsOptions{ShowStdout: true})
	if err != nil {
		return err
	}
	_, err = stdcopy.StdCopy(os.Stdout, os.Stderr, out)
	return err
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "%s\n", "usage: ACTION [args]")
		return
	}
	c, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		logrus.Fatalf("Unable to create Docker client, is Docker installed and running? %s", err)
	}
	ctx := context.Background()
	args := os.Args[1:]
	action := args[0]
	switch action {
	case "server":
		if err := buildContainer(ctx, c, "./hopd-dev.dockerfile", "hopd-dev"); err != nil {
			logrus.Fatalf("unable to build container: %s", err)
		}
		if err := runContainer(ctx, c, "hopd-dev", "7777"); err != nil {
			logrus.Fatalf("unable to run container: %s", err)
		}
	case "delegate":
		if err := buildContainer(ctx, c, "./delegate_proxy_server/delegate_proxy.dockerfile", "delegate_proxy_server"); err != nil {
			logrus.Fatalf("unable to build container: %s", err)
		}
		if err := runContainer(ctx, c, "delegate_proxy_server", "8888"); err != nil {
			logrus.Fatalf("unable to run container: %s", err)
		}
	case "target":
		if err := buildContainer(ctx, c, "./target_server/target_server.dockerfile", "target_server"); err != nil {
			logrus.Fatalf("unable to build container: %s", err)
		}
		if err := runContainer(ctx, c, "target_server", "9999"); err != nil {
			logrus.Fatalf("unable to run container: %s", err)
		}
	case "third":
		if err := buildContainer(ctx, c, "./third_server/third_server.dockerfile", "third_server"); err != nil {
			logrus.Fatalf("unable to build container: %s", err)
		}
		if err := runContainer(ctx, c, "third_server", "6666"); err != nil {
			logrus.Fatalf("unable to run container: %s", err)
		}
	case "measurement":
		if err := buildContainer(ctx, c, "./hopd-measurement.dockerfile", "hopd-measurement"); err != nil {
			logrus.Fatalf("unable to build container: %s", err)
		}
		if err := runContainer(ctx, c, "hopd-measurement", "7777"); err != nil {
			logrus.Fatalf("unable to run container: %s", err)
		}
	case "":
		fmt.Fprintf(os.Stderr, "%s\n", "usage: ACTION [args]")
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown action %q\n", action)
		return
	}
}
