class Agentlock < Formula
  desc "Locally-hosted, open-source firewall for AI coding agents"
  homepage "https://openagentlock.dev"
  url "https://registry.npmjs.org/@openagentlock/cli/-/cli-0.1.0.tgz"
  sha256 "REPLACE_ON_RELEASE"
  license "FSL-1.1-Apache-2.0"
  version "0.1.0"

  depends_on "bun"

  def install
    libexec.install Dir["*"]
    (bin/"agentlock").write <<~EOS
      #!/bin/bash
      exec bun --bun "#{libexec}/src/index.ts" "$@"
    EOS
    (bin/"agentlock").chmod 0755
  end

  def caveats
    <<~EOS
      OpenAgentLock has two pieces. The CLI you just installed is one.

      The control plane is a Docker container. Pull and start it with:

        curl -O https://raw.githubusercontent.com/openagentlock/openagentlock/main/docker-compose.yml
        docker compose up -d

      Then:

        agentlock detect
        agentlock install

      Documentation: https://openagentlock.dev/
    EOS
  end

  test do
    assert_match "agentlock", shell_output("#{bin}/agentlock --help 2>&1", 0)
  end
end
