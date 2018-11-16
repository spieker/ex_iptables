defmodule ExIptables do
  @moduledoc """
  This module provides wrapper functions around the iptables CLI. It uses
  adapters for executing the commands, in order to provide a convenient way to
  test your application.

  Use the `ExIptables.Adapters.FakeAdapter` for testing.
  """
  alias ExIptables.{Parser, Rule}

  @adapter Application.get_env(:ex_iptables, :adapter, ExIptables.Adapters.CliAdapter)

  def clear, do: @adapter.clear()

  @doc """
  Returns the adapter currently used by the application.

  ## Example

      iex> ExIptables.adapter()
      ExIptables.Adapters.FakeAdapter

  """
  def adapter, do: @adapter

  @doc """
  Append a rule to the end of the selected chain. When the source and/or
  destination names resolve to more than one address, a rule will be added for
  each possible address combination.

  ## Example

      iex> {:ok, _} = ExIptables.append("FORWARD", "-s 10.0.0.0/8 -j DROP")
      ...> ExIptables.list("FORWARD")
      {:ok, %Chain{name: "FORWARD", target: "ACCEPT", rules: [%Rule{source: {false, "10.0.0.0/8"}, jump: "DROP", rule: "-s 10.0.0.0/8 -j DROP"}]}}

      iex> {:ok, _} = ExIptables.append("FORWARD", "-s 10.10.10.10 -d 10.10.10.20 -j DROP")
      ...> ExIptables.list("FORWARD")
      {:ok, %Chain{name: "FORWARD", target: "ACCEPT", rules: [%Rule{source: {false, "10.10.10.10/32"}, destination: {false, "10.10.10.20/32"}, jump: "DROP", rule: "-s 10.10.10.10/32 -d 10.10.10.20/32 -j DROP"}]}}

      iex> ExIptables.append("MISSING", "-s 10.0.0.0/8 -j DROP")
      {:error, 1}
  """
  def append(chain, rule), do: @adapter.cmd(["--append", chain] ++ rule_to_args(rule))

  @doc """
  Check whether a rule matching the specification does exist in the selected
  chain. This command uses the same logic as `delete/2`.

  ## Example

      iex> {:ok, _} = ExIptables.append("FORWARD", "-s 10.0.0.0/8 -j DROP")
      ...> ExIptables.check("FORWARD", "-s 10.0.0.0/8 -j DROP")
      true

      iex> ExIptables.check("FORWARD", "-s 10.0.0.0/8 -j DROP")
      false

      iex> ExIptables.check("MISSING", "-s 10.0.0.0/8 -j DROP")
      false

  """
  def check(chain, rule) do
    case @adapter.cmd(["--check", chain] ++ rule_to_args(rule)) do
      {:ok, ""} -> true
      {:error, _} -> false
    end
  end

  @doc """
  Delete the matching rules from the selected chain.

  ## Example

      iex> {:ok, _} = ExIptables.append("FORWARD", "-s 10.0.0.0/8 -j DROP")
      ...> {:ok, %Chain{rules: rules}} = ExIptables.list("FORWARD")
      ...> 1 = Enum.count(rules)
      ...> {:ok, _} = ExIptables.delete("FORWARD", "-s 10.0.0.0/8 -j DROP")
      ...> ExIptables.list("FORWARD")
      {:ok, %Chain{name: "FORWARD", target: "ACCEPT", rules: []}}

      iex> ExIptables.delete("FORWARD", "-s 10.0.0.0/8 -j DROP")
      {:error, 1}

      iex> ExIptables.delete("MISSING", "-s 10.0.0.0/8 -j DROP")
      {:error, 1}

  """
  def delete(chain, rule), do: @adapter.cmd(["--delete", chain] ++ rule_to_args(rule))

  @doc """
  Insert one or more rules in the selected chain as the given rule number. So,
  if the rule number is 1, the rule or rules are inserted at the head of the
  chain.

  ## Example

      iex> ExIptables.append("FORWARD", "-s 10.1.0.0/16 --jump DROP")
      ...> ExIptables.append("FORWARD", "--source 10.3.0.0/16 -j DROP")
      ...> ExIptables.insert("FORWARD", 2, "--source 10.2.0.0/16      --jump       DROP")
      ...> ExIptables.list("FORWARD")
      {:ok, %Chain{
        name: "FORWARD",
        rules: [
          %Rule{jump: "DROP", source: {false, "10.1.0.0/16"}, rule: "-s 10.1.0.0/16 -j DROP"},
          %Rule{jump: "DROP", source: {false, "10.2.0.0/16"}, rule: "-s 10.2.0.0/16 -j DROP"},
          %Rule{jump: "DROP", source: {false, "10.3.0.0/16"}, rule: "-s 10.3.0.0/16 -j DROP"}
        ]
      }}

  """
  def insert(chain, rulenum, rule),
    do: @adapter.cmd(["--insert", chain, "#{rulenum}"] ++ rule_to_args(rule))

  @doc """
  Replace a rule in the selected chain. If the source and/or destination names
  resolve to multiple addresses, the command will fail. Rules are numbered
  starting at 1.
  """
  def replace(chain, rulenum, rule),
    do: @adapter.cmd(["--replace", chain, rulenum] ++ rule_to_args(rule))

  @doc """
  List all chains including the rules.

  ## Example

      iex> ExIptables.list()
      {:ok, [
              %Chain{name: "FORWARD", rules: [], target: "ACCEPT"},
              %Chain{name: "INPUT", rules: [], target: "ACCEPT"},
              %Chain{name: "OUTPUT", rules: [], target: "ACCEPT"}
            ]}

  """
  def list() do
    @adapter.cmd(["--list-rules"])
    |> handle_list_rules_result()
  end

  @doc """
  List the selected chain including the rules.

  ## Example

      iex> ExIptables.list("FORWARD")
      {:ok, %Chain{name: "FORWARD", target: "ACCEPT", rules: []}}

      iex> ExIptables.list("MISSING")
      {:error, 1}

  """
  def list(chain) do
    case ["--list-rules", chain] |> @adapter.cmd() |> handle_list_rules_result() do
      {:ok, list} -> {:ok, List.first(list)}
      error -> error
    end
  end

  @doc """
  Flushes all chains in the table. This is equivalent to deleting all the rules
  one by one.
  """
  def flush(), do: @adapter.cmd(["--flush"])

  @doc """
  Flushes all chains in given chain. This is equivalent to deleting all the
  rules one by one.
  """
  def flush(chain), do: @adapter.cmd(["--flush", chain])

  @doc """
  Zero the packet and byte counters in all chains.
  """
  def zero(), do: @adapter.cmd(["--zero"])

  @doc """
  Zero the packet and byte counters in the given chain.
  """
  def zero(chain), do: @adapter.cmd(["--zero", chain])

  @doc """
  Zero the packet and byte counters of the given rule in a chain.
  """
  def zero(chain, rulenum), do: @adapter.cmd(["--zero", chain, rulenum])

  @doc """
  Create a new user-defined chain by the given name. There must be no target of
  that name already.
  """
  def new_chain(chain), do: @adapter.cmd(["--new-chain", chain])

  @doc """
  Delete all optional user-defined chains. There must be no references to the
  chains. If there are, you must delete or replace the referring rules before
  the chains can be deleted. The chains must be empty, i.e. not contain any
  rules.
  """
  def delete_chain(), do: @adapter.cmd(["--delete-chain"])

  @doc """
  Delete the optional user-defined chain specified. There must be no references
  to the chain. If there are, you must delete or replace the referring rules
  before the chain can be deleted. The chain must be empty, i.e. not contain any
  rules.
  """
  def delete_chain(chain), do: @adapter.cmd(["--delete-chain", chain])

  @doc """
  Set the policy for the chain to the given target. See the section TARGETS for
  the legal targets. Only built-in (non-user-defined) chains can have policies,
  and neither built-in nor user-defined chains can be policy targets.

  ## Example

      iex> ExIptables.policy("FORWARD", "DROP")
      ...> ExIptables.list("FORWARD")
      {:ok, %Chain{name: "FORWARD", target: "DROP", rules: []}}

      iex> ExIptables.policy("MISSING", "DROP")
      {:error, 1}

  """
  def policy(chain, target), do: @adapter.cmd(["--policy", chain, target])

  @doc """
  Rename the user specified chain to the user supplied name. This is cosmetic,
  qand has no effect on the structure of the table.
  """
  def rename_chain(old_name, new_name), do: @adapter.cmd(["--rename-chain", old_name, new_name])

  defp rule_to_args(rule) when is_binary(rule), do: Parser.split_string(rule)
  defp rule_to_args(rule) when is_list(rule), do: Parser.normalize_args(rule)
  defp rule_to_args(%Rule{rule: rule}), do: rule_to_args(rule)

  def handle_list_rules_result({:error, _} = error), do: error
  def handle_list_rules_result({:ok, value}), do: Parser.parse(value)
end
