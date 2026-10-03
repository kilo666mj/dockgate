# dockgate

dockgate watches a small fleet of Docker hosts from one place. An agent on
each host reports containers, images, available image updates and
vulnerability scans to a central server. The server gates image updates on
the scan of the new image, reports containers that break policy, and pins
every agent to an enrolled key.

Status: early development. See [PLAN.md](PLAN.md) for the design and phases.

## Build and test

```sh
go build ./...
go test -race ./...
go vet ./...
```

## Deploy

```sh
cd ansible
cp inventory.example inventory   # then set the real host
ansible-playbook playbook.yml
```

The playbook builds locally, installs a hardened systemd unit, and waits until
`/version` reports the deployed commit.

## License

MIT. See [LICENSE](LICENSE).
