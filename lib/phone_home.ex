defmodule Misc.Living do
  @moduledoc """
  Ι notify the given pid when I spawn with the message :alive
  """
  def start_link(%{call: {mod, func, val}, pid: pid}) do
    ret = apply(mod, func, val)
    send(pid, :alive)
    ret
  end

  def child_spec(%{mod: mod, initial_value: val, pid: pid}) do
    %{start: func} = mod.child_spec(val)
    %{id: __MODULE__, start: {__MODULE__, :start_link, [%{call: func, pid: pid}]}}
  end

  def child_spec(pod) do
    start_link(Map.put(pod, :initial_value, []))
  end
end
