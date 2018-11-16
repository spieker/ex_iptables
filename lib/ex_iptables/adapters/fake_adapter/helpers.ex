defmodule ExIptables.Adapters.FakeAdapter.Helpers do
  alias ExIptables.{Chain, Parser, Rule}

  def chain(state, name) do
    case Map.get(state, name) do
      nil -> {:error, 1}
      result -> {:ok, result}
    end
  end

  def rule?(state, chain, %Rule{} = rule) do
    case chain(state, chain) do
      {:ok, %Chain{rules: rules}} ->
        case Enum.member?(rules, rule) do
          true -> {:ok, ""}
          false -> {:error, 1}
        end

      {:error, _} = error ->
        error
    end
  end

  def rule?(state, chain_name, args), do: rule?(state, chain_name, args_to_rule(args))

  def append_rule(state, chain_name, %Rule{} = rule) do
    case chain(state, chain_name) do
      {:ok, %Chain{rules: rules} = chain} ->
        chain = %Chain{chain | rules: rules ++ [rule]}
        new_state = Map.put(state, chain.name, chain)
        {:ok, new_state}

      {:error, _} = error ->
        error
    end
  end

  def append_rule(state, chain_name, args),
    do: append_rule(state, chain_name, args_to_rule(args))

  def insert_rule(state, chain_name, rulenum, %Rule{} = rule) when is_binary(rulenum) do
    case chain(state, chain_name) do
      {:ok, %Chain{rules: rules} = chain} ->
        {rulenum, _} = Integer.parse(rulenum)
        chain = %Chain{chain | rules: List.insert_at(rules, rulenum - 1, rule)}
        new_state = Map.put(state, chain.name, chain)
        {:ok, new_state}

      {:error, _} = error ->
        error
    end
  end

  def insert_rule(state, chain_name, rulenum, args) when is_binary(rulenum),
    do: insert_rule(state, chain_name, rulenum, args_to_rule(args))

  def delete_rule(state, chain_name, %Rule{} = rule) do
    case rule?(state, chain_name, rule) do
      {:ok, ""} ->
        {:ok, %Chain{rules: rules} = chain} = chain(state, chain_name)
        chain = %Chain{chain | rules: List.delete(rules, rule)}
        new_state = Map.put(state, chain_name, chain)
        {:ok, new_state}

      {:error, _} = error ->
        error
    end
  end

  def delete_rule(state, chain_name, args),
    do: delete_rule(state, chain_name, args_to_rule(args))

  def set_policy(state, chain_name, target) do
    case chain(state, chain_name) do
      {:ok, %Chain{} = chain} ->
        chain = %Chain{chain | target: target}
        new_state = Map.put(state, chain_name, chain)
        {:ok, new_state}

      {:error, _} = error ->
        error
    end
  end

  defp args_to_rule(args) do
    {_, args} =
      Enum.reduce(args, {nil, []}, fn
        "-s", {nil, result} -> {:source, result ++ ["-s"]}
        "-d", {nil, result} -> {:destination, result ++ ["-d"]}
        value, {:source, result} -> {nil, result ++ [ip_to_cidr(value)]}
        value, {:destination, result} -> {nil, result ++ [ip_to_cidr(value)]}
        value, {_, result} -> {nil, result ++ [value]}
      end)

    Parser.parse_rule(args)
  end

  defp ip_to_cidr(value) do
    case value |> String.split("/", parts: 2) |> Enum.count() do
      1 -> "#{value}/32"
      _ -> value
    end
  end
end
