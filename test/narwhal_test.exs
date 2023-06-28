defmodule MiscTest.Narwhal do

  use ExUnit.Case, async: true

  # import Misc.Narwhal.Validator
  import Misc.Narwhal.Primary

  alias Misc.Narwhal.Types, as: T

  doctest Misc

  test "Signing works on round 0" do
    {:ok, pid} = Misc.Narwhal.Validator.start_link(3)

    p_pid = Misc.Narwhal.Validator.get_primary(pid)

    {pub, priv} = :crypto.generate_key(:rsa, {1024,65537})

    block = %T.BlockStructure_1{block: T.Block_1.new(), round: 0, pub_key: pub}

    _signed = T.BlockStructure_1.sign(block, priv)

    signed_block = %T.SignedBlock_1{struct: block, signature: T.BlockStructure_1.sign(block, priv)}

    assert sign_block(p_pid, signed_block) != :error
  end

  test "State transition happens as we expect" do

    {:ok, pid} = Misc.Narwhal.Validator.start_link(3)

    p_pid = Misc.Narwhal.Validator.get_primary(pid)


    # this will have to change when we actually validate
    assert new_certificate(p_pid, 5) == :ack
    assert new_certificate(p_pid, 5) == :ack

    assert is_map(new_certificate(p_pid, 5)) # trigger mode change

    assert is_bitstring (new_certificate(p_pid, 5)) # should not understand

  end

  test "We go back into block creation properly" do

    {:ok, pid} = Misc.Narwhal.Validator.start_link(3)

    p_pid = Misc.Narwhal.Validator.get_primary(pid)

    new_certificate(p_pid, 5)

    new_certificate(p_pid, 5)

    signed_block = new_certificate(p_pid, 5)

    {:ok, pid_2} = Misc.Narwhal.Validator.start_link(3)

    p_pid_2 = Misc.Narwhal.Validator.get_primary(pid_2)

    signature = sign_block(p_pid_2, signed_block)

    assert new_signature(p_pid, signature) == :ack

    # in real code check for duplicates
    assert new_signature(p_pid, signature) == :ack

    transition = new_signature(p_pid, signature)

    # assert we have the required signatures
    assert length(transition.signatures) == 3

    # the round updates
    assert (get_state p_pid).network.round == 1

    # make sure we include our own cert
    assert length((get_state p_pid).data.certificates) == 1
  end



end
