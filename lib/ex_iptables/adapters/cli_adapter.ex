defmodule ExIptables.Adapters.CliAdapter do
  @moduledoc """
  This is the default adapter and uses the iptables CLI.
  """
  @bin "iptables"

  def cmd(args) do
    case System.cmd(@bin, args) do
      {result, 0} -> {:ok, result}
      {_result, error_code} -> {:error, error_code}
    end
  end

  def clear do
    with {:ok, _} <- cmd(["--policy", "INPUT", "ACCEPT"]),
         {:ok, _} <- cmd(["--policy", "FORWARD", "ACCEPT"]),
         {:ok, _} <- cmd(["--policy", "OUTPUT", "ACCEPT"]),
         {:ok, _} <- cmd(["--table", "nat", "--flush"]),
         {:ok, _} <- cmd(["--table", "mangle", "--flush"]),
         {:ok, _} <- cmd(["--flush"]),
         {:ok, _} <- cmd(["--delete-chain"]) do
      :ok
    else
      error -> error
    end
  end
end
