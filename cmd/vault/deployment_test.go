package main

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type envVar struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

// A deployment that runs more than one replica must use a token store the replicas share. With the in-memory
// default each pod keeps its own mappings and loses them on restart.
func TestShippedKubernetesDeploymentUsesASharedTokenStore(t *testing.T) {
	f, err := os.Open("../../deployments/k8s/deployment.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	checked := false
	for {
		var doc struct {
			Kind string `yaml:"kind"`
			Spec struct {
				Replicas int `yaml:"replicas"`
				Template struct {
					Spec struct {
						Containers []struct {
							Env []envVar `yaml:"env"`
						} `yaml:"containers"`
					} `yaml:"spec"`
				} `yaml:"template"`
			} `yaml:"spec"`
		}
		if dec.Decode(&doc) != nil {
			break
		}
		if doc.Kind != "Deployment" {
			continue
		}
		checked = true
		assertSharedStore(t, "kubernetes", doc.Spec.Template.Spec.Containers[0].Env)
	}
	if !checked {
		t.Fatal("no Deployment found")
	}
}

func assertSharedStore(t *testing.T, where string, env []envVar) {
	t.Helper()
	got := map[string]bool{}
	for _, e := range env {
		got[e.Name] = true
		if e.Name == "VAULT_TOKEN_STORE_DRIVER" && e.Value != "postgres" {
			t.Errorf("%s: token store driver is %q, want postgres", where, e.Value)
		}
		if e.Name == "VAULT_DATABASE_DSN" {
			t.Errorf("%s: VAULT_DATABASE_DSN is set but nothing reads it", where)
		}
	}
	for _, name := range []string{"VAULT_TOKEN_STORE_DRIVER", "VAULT_TOKEN_STORE_DSN"} {
		if !got[name] {
			t.Errorf("%s: %s is not set, so the in-memory store is used", where, name)
		}
	}
}

func TestShippedComposeUsesPostgresAndCreatesTheTable(t *testing.T) {
	raw, err := os.ReadFile("../../deployments/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]struct {
			Environment map[string]string `yaml:"environment"`
			Volumes     []string          `yaml:"volumes"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var env []envVar
	for k, v := range doc.Services["vault"].Environment {
		env = append(env, envVar{k, v})
	}
	assertSharedStore(t, "compose", env)

	initialised := false
	for _, v := range doc.Services["postgres"].Volumes {
		host, target, _ := strings.Cut(v, ":")
		if !strings.HasPrefix(target, "/docker-entrypoint-initdb.d") {
			continue
		}
		path := "../../deployments/" + strings.TrimPrefix(host, "./")
		files := []string{path}
		if entries, err := os.ReadDir(path); err == nil {
			files = files[:0]
			for _, e := range entries {
				files = append(files, path+"/"+e.Name())
			}
		}
		for _, f := range files {
			if b, err := os.ReadFile(f); err == nil && strings.Contains(string(b), "token_mappings") {
				initialised = true
			}
		}
	}
	if !initialised {
		t.Error("compose: nothing creates the token_mappings table, so every token write would fail")
	}
}
