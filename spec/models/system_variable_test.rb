require 'rails_helper'

RSpec.describe SystemVariable, type: :model do
  fixtures :all

  it "should have a fixture bar with value 34" do
    l = system_variables(:one)
    expect(l).to_not be_nil
    expect(l.variable).to eq("bar")
    expect(l.value).to    eq(34.to_s)
  end

  it "should look up name by symbol" do
    l = SystemVariable.lookup(:bar)
    expect(l).to_not be_nil
    expect(l.value).to    eq(34.to_s)
  end

  it "should make a variable if it does not already exist" do
    l = SystemVariable.findormake(:niceone)
    expect(l).to_not be_nil
    expect(l.value).to    be nil
  end

  it "should support nextvalue counters" do
    l = SystemVariable.nextval(:counter)
    expect(l).to eq(1)

    l = SystemVariable.nextval(:counter)
    expect(l).to eq(2)

    g = SystemVariable.findormake(:counter)
    expect(g.number).to eq(3)
  end

  it "should generate a sequence of random numbers" do
    l = SystemVariable.nextval(:counter)
    expect(l).to eq(1)

    l = SystemVariable.randomseq(:counter)
    expect(l).to_not eq 0
    #puts "l: #{l}"
    l = SystemVariable.randomseq(:counter)
    expect(l).to_not eq 0
    #puts "l: #{l}"
    l = SystemVariable.randomseq(:counter)
    expect(l).to_not eq 0
    #puts "l: #{l}"
  end


end
