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

func buildContainer(ctx context.Context, c *client.Client) error {
	// This only works because the Dockerfile is in the same root as the container.
	path := filepath.Join(data.Workspace(), "containers")
	t, err := archive.TarWithOptions(path, &archive.TarOptions{})
	if err != nil {
		return err
	}
	res, err := c.ImageBuild(ctx, t, types.ImageBuildOptions{
		Dockerfile: "hopd-dev.dockerfile",
		Tags:       []string{"hopd-dev"},
		Remove:     true,
	})
	if err != nil {
		return err
	}
	defer res.Body.Close()
	io.Copy(os.Stdout, res.Body)
	return nil
}

func runContainer(ctx context.Context, c *client.Client) error {
	containerConfig := container.Config{
		Image:        "hopd-dev",
		Volumes:      map[string]struct{}{"/app": {}},
		ExposedPorts: nat.PortSet{"77/udp": {}},
	}
	hostConfig := container.HostConfig{
		Mounts: []mount.Mount{
			{
				Type:     mount.TypeBind,
				Source:   data.Workspace(),
				Target:   "/app",
				ReadOnly: true,
			},
		},
		PortBindings: nat.PortMap{"77/udp": []nat.PortBinding{{HostIP: "127.0.0.1", HostPort: "7777"}}},
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
		if err := buildContainer(ctx, c); err != nil {
			logrus.Fatalf("unable to build container: %s", err)
		}
		if err := runContainer(ctx, c); err != nil {
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
