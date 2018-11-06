defmodule ExIptables.Chain do
  @moduledoc """
  This module is representing an iptables chain.
  """
  defstruct name: nil,
            target: "ACCEPT",
            rules: []
end
