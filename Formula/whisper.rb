# Homebrew Formula for Whisper
# Install via: brew tap phpfc/whisper && brew install whisper

class Whisper < Formula
  desc "Secure P2P chat in the terminal. Zero config, no servers needed"
  homepage "https://github.com/phpfc/whisper"
  url "https://github.com/phpfc/whisper/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "PLACEHOLDER"
  license "MIT"
  head "https://github.com/phpfc/whisper.git", branch: "main"

  bottle do
    root_url "https://github.com/phpfc/whisper/releases/download/v0.2.0"
    rebuild 0
    sha256 cellar: :any_skip_relocation, arm64_sonoma: "PLACEHOLDER"
  end

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "whisper 0.2.0", shell_output("#{bin}/whisper --version")
  end
end
